package httpapi

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"selfu/internal/access"
	"selfu/internal/dns"
	"selfu/internal/domain"
	"selfu/internal/store"
)

// humanizeCloudflareErr maps raw Cloudflare client errors to operator-
// friendly text; unknown shapes pass through unchanged.
func humanizeCloudflareErr(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "status 401"), strings.Contains(msg, "status 403"):
		return "Cloudflare rejected the API token — check the token and its Zone.Read/Zone.DNS permissions."
	case strings.Contains(msg, "no cloudflare zone found"):
		return msg
	default:
		return "Cloudflare API error: " + msg
	}
}

// bootstrapLoginLimiter throttles password guesses against the pre-
// onboarding local login. Fixed 1-minute window per client; behind the
// ingress all requests share the proxy address, so X-Forwarded-For (set
// by the trusted single-hop proxy) identifies the client.
type loginLimiter struct {
	mu    sync.Mutex
	fails map[string]*loginFails
}

type loginFails struct {
	count       int
	windowStart time.Time
}

const loginMaxFails = 10

var bootstrapLimiter = &loginLimiter{fails: map[string]*loginFails{}}

func clientKey(r *http.Request) string {
	if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
		if i := strings.IndexByte(xf, ','); i >= 0 {
			return strings.TrimSpace(xf[:i])
		}
		return strings.TrimSpace(xf)
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func (l *loginLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, ok := l.fails[key]
	if !ok || time.Since(f.windowStart) > time.Minute {
		return true
	}
	return f.count < loginMaxFails
}

func (l *loginLimiter) recordFail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, ok := l.fails[key]
	if !ok || time.Since(f.windowStart) > time.Minute {
		l.fails[key] = &loginFails{count: 1, windowStart: time.Now()}
		return
	}
	f.count++
}

func (l *loginLimiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, key)
}

// setupLoginReq is the bootstrap local login payload.
type setupLoginReq struct {
	Password string `json:"password"`
}

// setupLogin authenticates the bootstrap administrator against the
// pre-onboarding local credential (AUTHENTIK_BOOTSTRAP_PASSWORD) and issues
// the standard platform session cookie. Valid only until the installation
// is onboarded; afterwards OIDC is the only login path.
func (h *Handler) setupLogin(w http.ResponseWriter, r *http.Request) {
	inst, err := h.d.Setup.GetInstallation(r.Context())
	if err != nil {
		h.internalError(w, err)
		return
	}
	if inst.Onboarded() {
		writeError(w, http.StatusForbidden, "already_onboarded", "bootstrap login is disabled after onboarding")
		return
	}
	if h.d.BootstrapPassword == "" {
		writeError(w, http.StatusServiceUnavailable, "not_configured", "bootstrap password is not configured")
		return
	}
	var req setupLoginReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	key := clientKey(r)
	if !bootstrapLimiter.allow(key) {
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many attempts — wait a minute and retry")
		return
	}
	if subtle.ConstantTimeCompare([]byte(h.d.BootstrapPassword), []byte(req.Password)) != 1 {
		bootstrapLimiter.recordFail(key)
		h.audit(r.Context(), domain.AuditEvent{
			Action:       "auth.bootstrap_login.failed",
			ResourceType: "installation",
		})
		writeError(w, http.StatusUnauthorized, "unauthorized", "invalid bootstrap password")
		return
	}
	bootstrapLimiter.reset(key)

	email := h.d.BootstrapEmail
	if email == "" {
		email = "admin@" + domain.ValidateLocalDomain(inst.LocalDomain)
	}
	u, _, adminGranted, err := h.d.Users.UpsertFromOIDC(
		r.Context(), "local-bootstrap", "bootstrap", email, "Bootstrap Administrator")
	if err != nil {
		h.internalError(w, err)
		return
	}
	tok, err := h.d.Sessions.Issue(u.ID)
	if err != nil {
		h.internalError(w, err)
		return
	}
	h.d.Sessions.SetCookie(w, tok)

	h.audit(r.Context(), domain.AuditEvent{
		ActorUserID:  &u.ID,
		Action:       "auth.login.succeeded",
		ResourceType: "user",
		ResourceID:   u.ID,
		Details:      map[string]any{"provider": "local-bootstrap", "admin_granted": adminGranted},
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "email": u.Email, "admin_granted": adminGranted})
}

// setupStatus reports the onboarding state (public: used by the wizard
// page and the UI gate to decide redirects).
func (h *Handler) setupStatus(w http.ResponseWriter, r *http.Request) {
	inst, err := h.d.Setup.GetInstallation(r.Context())
	if err != nil {
		h.internalError(w, err)
		return
	}
	admins, aerr := h.d.Users.AdminCount(r.Context())
	if aerr != nil {
		h.internalError(w, aerr)
		return
	}
	resp := map[string]any{
		"onboarded":       inst.Onboarded(),
		"local_domain":    inst.LocalDomain,
		"bootstrap_email": h.d.BootstrapEmail,
		"admin_exists":    admins > 0,
	}
	// Expose pending onboarding state so the wizard can resume an
	// interrupted auto-verify after a reload (G8/G9).
	if !inst.Onboarded() && inst.PrimaryDomainID != "" {
		if d, err := h.d.DomainStore.GetDomainByID(r.Context(), inst.PrimaryDomainID); err == nil {
			resp["primary_domain"] = map[string]any{
				"id": d.ID, "fqdn": d.FQDN, "status": string(d.Status),
			}
			resp["provider"] = inst.AccessProvider
			// Surface the background auto-verify poller state so the
			// wizard can show live progress without manual action.
			if lc, res := h.verifySnapshot(); !lc.IsZero() {
				resp["auto_verify"] = map[string]any{
					"last_check":  lc,
					"last_result": res,
				}
			}
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// createSetupReq is the onboarding payload: the primary domain plus the
// external access provider configuration.
type createSetupReq struct {
	FQDN     string `json:"fqdn"`
	Provider string `json:"provider"`
	APIToken string `json:"api_token"`
	ZoneID   string `json:"zone_id"`
}

// createSetup runs the wizard step: registers the primary domain under a
// dedicated organization, validates and stores the access provider, and
// auto-provisions the verification TXT record.
func (h *Handler) createSetup(w http.ResponseWriter, r *http.Request) {
	admin := rUser(r)
	if !admin.IsAdmin {
		writeError(w, http.StatusForbidden, "forbidden", "platform admin required")
		return
	}
	inst, err := h.d.Setup.GetInstallation(r.Context())
	if err != nil {
		h.internalError(w, err)
		return
	}
	if inst.Onboarded() {
		writeError(w, http.StatusConflict, "already_onboarded", "installation is already onboarded")
		return
	}
	var req createSetupReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	// Validate the provider identifier (no network yet).
	prov, err := access.New(req.Provider, access.Config{
		APIToken: req.APIToken,
		ZoneID:   req.ZoneID,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	fqdn, err := domain.NormalizeDomain(req.FQDN)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if fqdn == domain.ValidateLocalDomain(inst.LocalDomain) {
		writeError(w, http.StatusBadRequest, "invalid_request", "primary domain must differ from the local domain")
		return
	}

	// Cloudflare requires an API token; the zone id is optional and
	// auto-resolved from the primary domain when omitted.
	if req.Provider == "cloudflare" {
		if strings.TrimSpace(req.APIToken) == "" {
			writeError(w, http.StatusBadRequest, "invalid_request",
				"cloudflare provider requires api_token")
			return
		}
		if strings.TrimSpace(req.ZoneID) == "" {
			var resolved string
			if h.d.ZoneResolver != nil {
				resolved, err = h.d.ZoneResolver(r.Context(), fqdn, req.APIToken)
			} else {
				resolved, err = prov.ResolveZone(r.Context(), fqdn)
			}
			if err != nil {
				writeError(w, http.StatusBadRequest, "zone_not_found", humanizeCloudflareErr(err))
				return
			}
			req.ZoneID = resolved
		}
		// Rebuild with the full config and verify the zone is reachable.
		prov, err = access.New(req.Provider, access.Config{
			APIToken: req.APIToken,
			ZoneID:   req.ZoneID,
		})
		if err != nil {
			h.internalError(w, err)
			return
		}
		if err := func() error {
			if h.d.ProviderProbe != nil {
				return h.d.ProviderProbe(r.Context(), prov)
			}
			return prov.Validate(r.Context())
		}(); err != nil {
			writeError(w, http.StatusUnprocessableEntity, "provider_unavailable", humanizeCloudflareErr(err))
			return
		}
	}

	// The primary domain lives in a dedicated organization owned by the
	// bootstrap admin.
	org, err := domain.NewOrganization(fqdn)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	createdOrg, err := h.d.IdentityStore.CreateOrganization(r.Context(), org)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "conflict", "organization for this domain already exists")
			return
		}
		h.internalError(w, err)
		return
	}
	if _, err := h.d.IdentityStore.SetMembership(r.Context(), createdOrg.ID, admin.ID, domain.RoleOwner); err != nil {
		h.internalError(w, err)
		return
	}

	d, err := domain.NewDomain(createdOrg.ID, fqdn)
	if err != nil {
		h.internalError(w, err)
		return
	}
	created, err := h.d.DomainStore.CreateDomain(r.Context(), d)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "conflict", "domain already registered")
			return
		}
		h.internalError(w, err)
		return
	}

	recordName := dns.VerifyRecordName(created.FQDN)
	recordValue := dns.TokenTXTValue(created.VerificationToken)
	automated := false
	if perr := h.d.AccessProvider.DNS().SetTXT(r.Context(), recordName, recordValue); perr == nil {
		automated = true
	}

	// Seal the provider credentials at rest with the platform key.
	cfgJSON, jerr := json.Marshal(access.Config{APIToken: req.APIToken, ZoneID: req.ZoneID})
	if jerr != nil {
		h.internalError(w, jerr)
		return
	}
	sealed, serr := EncryptSecret(h.d.EncryptionKey, string(cfgJSON))
	if serr != nil {
		h.internalError(w, serr)
		return
	}
	if err := h.d.Setup.SetInstallationProvider(r.Context(), prov.DNS().Name(), prov.Name(), sealed); err != nil {
		h.internalError(w, err)
		return
	}
	if err := h.d.Setup.SetInstallationPrimaryDomain(r.Context(), created.ID); err != nil {
		h.internalError(w, err)
		return
	}

	h.audit(r.Context(), domain.AuditEvent{
		ActorUserID:  &admin.ID,
		Action:       "setup.primary_domain",
		ResourceType: "domain",
		ResourceID:   created.ID,
		Details:      map[string]any{"fqdn": fqdn, "provider": prov.Name()},
	})

	writeJSON(w, http.StatusCreated, map[string]any{
		"domain": created,
		"verification": map[string]any{
			"record_name":  recordName,
			"record_value": recordValue,
			"automated":    automated,
		},
		"provider": prov.Name(),
	})
}

// verifySetup verifies the pending primary domain's TXT record and, on
// success, marks the installation onboarded. The logic lives in
// runVerifySetup so the background auto-verify poller reuses it verbatim.
func (h *Handler) verifySetup(w http.ResponseWriter, r *http.Request) {
	admin := rUser(r)
	if !admin.IsAdmin {
		writeError(w, http.StatusForbidden, "forbidden", "platform admin required")
		return
	}
	code, payload := h.runVerifySetup(r.Context(), admin.ID)
	writeJSON(w, code, payload)
}

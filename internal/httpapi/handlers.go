package httpapi

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"

	"github.com/google/uuid"

	"selfu/internal/auth"
	"selfu/internal/config"
	"selfu/internal/dns"
	"selfu/internal/domain"
	"selfu/internal/store"
	"selfu/internal/version"
)

// OIDCClient is the OIDC surface the handlers depend on.
type OIDCClient interface {
	AuthCodeURL(state, nonce string) string
	Exchange(ctx context.Context, code, expectedNonce string) (auth.OIDCIdentity, error)
}

// UserStore is the user persistence the handlers need.
type UserStore interface {
	UpsertFromOIDC(ctx context.Context, provider, subject, email, displayName string) (domain.User, bool, bool, error)
	GetByID(ctx context.Context, id string) (domain.User, error)
}

// AuditStore persists audit events.
type AuditStore interface {
	CreateAuditEvent(ctx context.Context, e domain.AuditEvent) error
}

// Deps wires the handler dependencies; New builds the full router from it.
type Deps struct {
	Logger         *slog.Logger
	Sessions       *auth.SessionStore
	OIDC           OIDCClient
	Users          UserStore
	Audit          AuditStore
	OIDCConfig     config.OIDCConfig
	AfterLoginPath string

	// IdentityStore is the identity persistence surface (G2).
	IdentityStore IdentityStore
	// Identity provisions external identities in authentik.
	Identity IdentityClient
	// ProviderName labels external_resources (the authentik issuer).
	ProviderName string

	// DomainStore is the domain/hostname persistence surface (G3).
	DomainStore DomainStore
	// DNSProvider auto-provisions records (manual by default for v0).
	DNSProvider dns.Provider
	// TXTLookup queries TXT records for domain verification.
	TXTLookup dns.TXTLookup
}

// Handler serves the REST API and the OIDC login flow.
type Handler struct {
	d Deps
}

// audit writes an audit event; failures are logged but never fail the
// originating request (auditing is at-least-once best effort).
func (h *Handler) audit(ctx context.Context, e domain.AuditEvent) {
	e.ID = uuid.NewString()
	e.RequestID = requestIDFrom(ctx)
	if err := h.d.Audit.CreateAuditEvent(ctx, e); err != nil {
		h.d.Logger.Error("audit write failed", "err", err, "action", e.Action)
	}
}

func (h *Handler) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"version": version.Version,
	})
}

// oidcLogin starts the authorization code flow: random state+nonce stored
// in a short-lived cookie, browser redirected to authentik.
func (h *Handler) oidcLogin(w http.ResponseWriter, r *http.Request) {
	state, err := auth.RandomToken(18)
	if err != nil {
		h.internalError(w, err)
		return
	}
	nonce, err := auth.RandomToken(18)
	if err != nil {
		h.internalError(w, err)
		return
	}
	if err := h.d.Sessions.SetOIDCStateCookie(w, auth.OIDCState{State: state, Nonce: nonce}); err != nil {
		h.internalError(w, err)
		return
	}
	http.Redirect(w, r, h.d.OIDC.AuthCodeURL(state, nonce), http.StatusFound)
}

// oidcCallback completes the code exchange, upserts the platform user and
// issues the platform session cookie (spec §15).
func (h *Handler) oidcCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if oidcErr := r.URL.Query().Get("error"); oidcErr != "" {
		h.audit(ctx, domain.AuditEvent{
			Action:  "auth.oidc.failed",
			Details: map[string]any{"reason": oidcErr},
		})
		http.Redirect(w, r, h.d.AfterLoginPath, http.StatusFound)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "missing authorization code")
		return
	}

	st, err := h.d.Sessions.GetOIDCStateCookie(r)
	if err != nil {
		h.audit(ctx, domain.AuditEvent{
			Action:  "auth.oidc.failed",
			Details: map[string]any{"reason": "missing or invalid state cookie"},
		})
		writeError(w, http.StatusBadRequest, "invalid_state", "missing or invalid state cookie")
		return
	}
	h.d.Sessions.ClearOIDCStateCookie(w)

	qState := r.URL.Query().Get("state")
	if subtle.ConstantTimeCompare([]byte(qState), []byte(st.State)) != 1 {
		h.audit(ctx, domain.AuditEvent{
			Action:  "auth.oidc.failed",
			Details: map[string]any{"reason": "state mismatch"},
		})
		writeError(w, http.StatusBadRequest, "state_mismatch", "state mismatch")
		return
	}

	identity, err := h.d.OIDC.Exchange(ctx, code, st.Nonce)
	if err != nil {
		h.d.Logger.Warn("oidc exchange failed", "err", err)
		h.audit(ctx, domain.AuditEvent{
			Action:  "auth.oidc.failed",
			Details: map[string]any{"reason": "token exchange failed"},
		})
		writeError(w, http.StatusUnauthorized, "authentication_failed", "login failed")
		return
	}

	user, created, adminGranted, err := h.d.Users.UpsertFromOIDC(
		ctx, h.d.OIDCConfig.Issuer, identity.Subject, identity.Email, identity.DisplayName)
	if err != nil {
		h.d.Logger.Error("user upsert failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "could not create session")
		return
	}

	token, err := h.d.Sessions.Issue(user.ID)
	if err != nil {
		h.internalError(w, err)
		return
	}
	h.d.Sessions.SetCookie(w, token)

	h.audit(ctx, domain.AuditEvent{
		ActorUserID:  &user.ID,
		Action:       "auth.login.succeeded",
		ResourceType: "user",
		ResourceID:   user.ID,
		Details:      map[string]any{"created": created, "admin_granted": adminGranted},
	})
	if adminGranted {
		h.audit(ctx, domain.AuditEvent{
			ActorUserID:  &user.ID,
			Action:       "user.admin_granted",
			ResourceType: "user",
			ResourceID:   user.ID,
		})
	}

	http.Redirect(w, r, h.d.AfterLoginPath, http.StatusFound)
}

// me returns the authenticated user.
func (h *Handler) me(w http.ResponseWriter, _ *http.Request, u domain.User) {
	writeJSON(w, http.StatusOK, u)
}

// requireAuth gates a handler behind a valid platform session.
func (h *Handler) requireAuth(next func(http.ResponseWriter, *http.Request, domain.User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(h.d.Sessions.CookieName())
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorized", "missing session")
			return
		}
		sess, err := h.d.Sessions.Validate(c.Value)
		if err != nil {
			h.d.Sessions.ClearCookie(w)
			writeError(w, http.StatusUnauthorized, "unauthorized", "invalid or expired session")
			return
		}
		u, err := h.d.Users.GetByID(r.Context(), sess.UserID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				h.d.Sessions.ClearCookie(w)
				writeError(w, http.StatusUnauthorized, "unauthorized", "user not found")
				return
			}
			h.internalError(w, err)
			return
		}
		next(w, r, u)
	}
}

func (h *Handler) internalError(w http.ResponseWriter, err error) {
	h.d.Logger.Error("internal error", "err", err)
	writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
}

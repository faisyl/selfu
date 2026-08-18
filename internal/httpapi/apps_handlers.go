package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"selfu/internal/authentik"
	"selfu/internal/catalog"
	"selfu/internal/chasquid"
	"selfu/internal/domain"
	"selfu/internal/store"
	"selfu/internal/traefik"
)

// AppStore is the application persistence surface. *store.Store satisfies it.
type AppStore interface {
	CreateCatalogApp(ctx context.Context, m *catalog.Manifest) (string, error)
	GetCatalogAppByID(ctx context.Context, id string) (store.CatalogApp, error)
	ListCatalogApps(ctx context.Context) ([]store.CatalogApp, error)

	CreateApplicationInstance(ctx context.Context, orgID, catalogID, name, slug string) (string, error)
	GetInstance(ctx context.Context, id string) (store.Instance, error)
	ListInstancesByOrg(ctx context.Context, orgID string) ([]store.Instance, error)
	SetInstanceStatus(ctx context.Context, id, status string) error

	AddInstanceHostname(ctx context.Context, instanceID, hostname string) error
	AddInstanceAccessGroup(ctx context.Context, instanceID, groupID string) error
}

// AppProvisioner provisions per-app OIDC (spec §82) and forward-auth
// (spec §83) providers. *authentik.Client satisfies it (wired as
// Deps.Identity in cmd/api).
type AppProvisioner interface {
	EnsureAppOIDC(ctx context.Context, name, slug, redirectURI string) (authentik.AppOIDC, error)
	EnsureForwardAuth(ctx context.Context, name, slug, externalHost string) (authentik.AppOIDC, error)
}

func (h *Handler) listCatalog(w http.ResponseWriter, r *http.Request) {
	if !rUser(r).IsAdmin {
		writeError(w, http.StatusForbidden, "forbidden", "platform admin required")
		return
	}
	apps, err := h.d.Apps.ListCatalogApps(r.Context())
	if err != nil {
		h.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, apps)
}

type registerCatalogReq struct {
	Manifest string `json:"manifest"` // yaml (strict; unknown fields rejected)
}

func (h *Handler) registerCatalog(w http.ResponseWriter, r *http.Request) {
	if !rUser(r).IsAdmin {
		writeError(w, http.StatusForbidden, "forbidden", "platform admin required")
		return
	}
	var req registerCatalogReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	m, err := catalog.Parse([]byte(req.Manifest))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_manifest", err.Error())
		return
	}
	id, err := h.d.Apps.CreateCatalogApp(r.Context(), m)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "conflict", "catalog entry already exists")
			return
		}
		h.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "slug": m.ID, "version": m.Version})
}

type createApplicationReq struct {
	CatalogID      string   `json:"catalog_id"`
	Hostname       string   `json:"hostname"`
	Name           string   `json:"name"`
	AccessGroupIDs []string `json:"access_group_ids"`
}

// createApplication installs an app from the catalog (spec §82): hostname
// must sit within a verified org domain; an authentik OIDC provider is
// provisioned for oidc apps; an app SMTP identity + unique credential +
// sender policy when email is required (§44–46, §70–73).
func (h *Handler) createApplication(w http.ResponseWriter, r *http.Request) {
	orgID := r.PathValue("id")
	if !h.requireOrgRole(w, r, orgID, domain.RoleAdmin) {
		return
	}
	var req createApplicationReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	catalogApp, err := h.d.Apps.GetCatalogAppByID(r.Context(), req.CatalogID)
	if err != nil || catalogApp.Manifest == nil {
		writeError(w, http.StatusBadRequest, "invalid_catalog", "catalog entry not found")
		return
	}
	m := catalogApp.Manifest

	dom, hostname, ok := h.findVerifiedOrgDomain(r.Context(), orgID, req.Hostname)
	if !ok {
		writeError(w, http.StatusBadRequest, "hostname_not_available",
			"hostname must be within a verified domain of this organization")
		return
	}

	name := req.Name
	if name == "" {
		name = m.Metadata.Name
	}
	instanceID, err := h.d.Apps.CreateApplicationInstance(r.Context(), orgID, catalogApp.ID, name, slugifyInstance(name))
	if err != nil {
		h.internalError(w, err)
		return
	}
	if err := h.d.Apps.AddInstanceHostname(r.Context(), instanceID, hostname); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "conflict", "hostname already bound")
			return
		}
		h.internalError(w, err)
		return
	}
	for _, g := range req.AccessGroupIDs {
		_ = h.d.Apps.AddInstanceAccessGroup(r.Context(), instanceID, g)
	}

	resp := map[string]any{"instance_id": instanceID, "name": name, "hostname": hostname}
	slug := slugifyInstance(name)
	forwardAuth := m.Authentication.Mode == catalog.AuthForwardAuth
	port := 80
	if m.Network.HTTP != nil {
		port = m.Network.HTTP.ContainerPort
	}
	resp["traefik"] = traefik.RouteLabels(instanceID, hostname, port, forwardAuth)

	// OIDC: provision an authentik provider + application (§82).
	switch {
	case m.Authentication.Mode == catalog.AuthOIDC && h.d.Identity != nil:
		p, ok := h.d.Identity.(AppProvisioner)
		if !ok {
			break
		}
		redirect := "https://" + hostname + ".*"
		oidc, err := p.EnsureAppOIDC(r.Context(), name, slug, redirect)
		if err != nil {
			h.d.Logger.Warn("app oidc provisioning failed", "err", err, "instance", instanceID)
		} else {
			_, _ = h.d.IdentityStore.UpsertExternalResource(r.Context(), domain.ExternalResource{
				ResourceType:     domain.ResTypeAuthentikProvider,
				PlatformObjectID: instanceID,
				Provider:         h.d.ProviderName,
				ExternalID:       strconv.Itoa(oidc.ProviderPK),
				Status:           domain.ExtActive,
			})
			_, _ = h.d.IdentityStore.UpsertExternalResource(r.Context(), domain.ExternalResource{
				ResourceType:     domain.ResTypeAuthentikApplication,
				PlatformObjectID: instanceID,
				Provider:         h.d.ProviderName,
				ExternalID:       oidc.ApplicationPK,
				Status:           domain.ExtActive,
			})
			resp["oidc"] = map[string]any{
				"client_id":     oidc.ClientID,
				"client_secret": oidc.ClientSecret,
				"redirect_uri":  redirect,
				"note":          "shown once; configure the application with these",
			}
		}
	case forwardAuth && h.d.Identity != nil:
		// Forward-auth provider + application (spec §83).
		p, ok := h.d.Identity.(AppProvisioner)
		if !ok {
			break
		}
		fa, err := p.EnsureForwardAuth(r.Context(), name, slug, "https://"+hostname)
		if err != nil {
			h.d.Logger.Warn("app forward-auth provisioning failed", "err", err, "instance", instanceID)
		} else {
			_, _ = h.d.IdentityStore.UpsertExternalResource(r.Context(), domain.ExternalResource{
				ResourceType:     domain.ResTypeAuthentikProvider,
				PlatformObjectID: instanceID,
				Provider:         h.d.ProviderName,
				ExternalID:       strconv.Itoa(fa.ProviderPK),
				Status:           domain.ExtActive,
			})
			_, _ = h.d.IdentityStore.UpsertExternalResource(r.Context(), domain.ExternalResource{
				ResourceType:     domain.ResTypeAuthentikApplication,
				PlatformObjectID: instanceID,
				Provider:         h.d.ProviderName,
				ExternalID:       fa.ApplicationPK,
				Status:           domain.ExtActive,
			})
			resp["forward_auth"] = map[string]any{"configured": true}
		}
	}

	// Email: an app SMTP identity + unique credential + policy (§44–46).
	if m.Email != nil && m.Email.Required && h.d.Chasquid != nil {
		local := m.Email.Sender.LocalPart
		if local == "" {
			local = "notifications"
		}
		addr := local + "-" + shortID(instanceID) + "@" + dom.FQDN
		if credID, secret, err := h.provisionAppIdentity(r.Context(), orgID, dom.ID, instanceID, addr); err == nil {
			resp["smtp"] = map[string]any{
				"address":       addr,
				"username":      addr,
				"credential_id": credID,
				"secret":        string(secret),
				"note":          "shown once; independent credential, never shared (spec §45)",
			}
		} else {
			h.d.Logger.Warn("app smtp identity failed", "err", err, "instance", instanceID)
		}
	}

	_ = h.d.Apps.SetInstanceStatus(r.Context(), instanceID, "active")
	h.audit(r.Context(), domain.AuditEvent{
		ActorUserID:  new(rUser(r).ID),
		Action:       "application.installed",
		ResourceType: "application_instance",
		ResourceID:   instanceID,
		Details:      map[string]any{"catalog": m.ID, "hostname": hostname},
	})
	writeJSON(w, http.StatusCreated, resp)
}

func (h *Handler) listApplications(w http.ResponseWriter, r *http.Request) {
	orgID := r.PathValue("id")
	if !h.requireOrgRole(w, r, orgID, domain.RoleMember) {
		return
	}
	list, err := h.d.Apps.ListInstancesByOrg(r.Context(), orgID)
	if err != nil {
		h.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// provisionAppIdentity creates a chasquid user, a unique SMTP credential and
// its sender policy for an application (spec §44–46, §70–73). Returns the
// credential id and the secret (shown once).
func (h *Handler) provisionAppIdentity(ctx context.Context, orgID, domID, instanceID, addr string) (string, chasquid.Secret, error) {
	secret, err := newSMTPSecret()
	if err != nil {
		return "", "", err
	}
	local := strings.SplitN(addr, "@", 2)[0]
	ident, err := h.d.MailStore.CreateMailIdentity(ctx, domain.MailIdentity{
		OrganizationID:   orgID,
		DomainID:         domID,
		LocalPart:        local,
		Address:          addr,
		ChasquidUsername: addr,
		Status:           domain.MailIdentityProvisioning,
	})
	if err != nil {
		return "", "", err
	}
	cred, err := h.d.MailStore.CreateMailCredential(ctx, domain.MailCredential{
		MailIdentityID:    ident.ID,
		SecretFingerprint: fingerprint(secret),
	})
	if err != nil {
		return "", "", err
	}
	if err := h.d.Chasquid.AddUser(ctx, addr, secret); err != nil {
		return "", "", err
	}
	_ = h.d.Chasquid.EnsureSenderPolicy(ctx, addr, []string{addr})
	_ = h.d.MailStore.CreateMailSubmissionPolicy(ctx, domain.MailSubmissionPolicy{
		MailIdentityID:        ident.ID,
		CredentialID:          cred.ID,
		AllowedFromAddresses:  []string{addr},
		ApplicationInstanceID: new(instanceID),
	})
	_ = h.d.MailStore.SetMailIdentityStatus(ctx, ident.ID, domain.MailIdentityActive)
	return cred.ID, secret, nil
}

// findVerifiedOrgDomain returns a verified org domain containing hostname.
func (h *Handler) findVerifiedOrgDomain(ctx context.Context, orgID, hostname string) (domain.Domain, string, bool) {
	domains, err := h.d.DomainStore.ListDomainsByOrg(ctx, orgID)
	if err != nil {
		return domain.Domain{}, "", false
	}
	norm, err := domain.NormalizeDomain(hostname)
	if err != nil {
		return domain.Domain{}, "", false
	}
	for _, d := range domains {
		if d.Status != domain.DomainVerified {
			continue
		}
		if domain.HostnameWithinDomain(norm, d.FQDN) {
			return d, norm, true
		}
	}
	return domain.Domain{}, "", false
}

func slugifyInstance(name string) string {
	s := domain.Slugify(name)
	if s == "" || s == "org" {
		s = "app"
	}
	return s
}

func shortID(id string) string {
	if len(id) > 6 {
		return id[:6]
	}
	return id
}

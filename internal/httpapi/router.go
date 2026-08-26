package httpapi

import "net/http"

// NewHandler assembles the API handler (same as New) while exposing the
// concrete *Handler so callers can start the background auto-verify
// poller.
func NewHandler(d Deps) *Handler {
	return &Handler{d: d}
}

// New assembles the full API router with middleware.
func New(d Deps) http.Handler {
	return (&Handler{d: d}).buildRouter()
}

// BuildRouter exposes the assembled router for callers holding the
// concrete *Handler (e.g. the API main that starts the verification
// poller).
func (h *Handler) BuildRouter() http.Handler { return h.buildRouter() }

// buildRouter wires the routes.
func (h *Handler) buildRouter() http.Handler {
	d := h.d
	mux := http.NewServeMux()
	mux.HandleFunc("GET /favicon.ico", h.favicon)
	mux.HandleFunc("GET /api/v1/health", h.health)
	mux.HandleFunc("GET /api/v1/setup", h.setupStatus)
	mux.HandleFunc("POST /api/v1/setup/login", h.setupLogin)
	mux.Handle("POST /api/v1/setup", h.authn(h.createSetup))
	mux.Handle("POST /api/v1/setup/verify", h.authn(h.verifySetup))
	mux.HandleFunc("POST /api/v1/auth/logout", h.logout)
	mux.HandleFunc("GET /api/v1/auth/login", h.oidcLogin)
	mux.HandleFunc("GET /api/v1/auth/callback", h.oidcCallback)
	mux.Handle("GET /api/v1/me", h.requireAuth(h.me))

	// G2 — identity.
	mux.Handle("POST /api/v1/organizations", h.authn(h.createOrganization))
	mux.Handle("GET /api/v1/organizations", h.authn(h.listOrganizations))
	mux.Handle("POST /api/v1/organizations/{id}/members", h.authn(h.addOrganizationMember))
	mux.Handle("POST /api/v1/organizations/{id}/onboard-user", h.authn(h.onboardUser))
	mux.Handle("POST /api/v1/organizations/{id}/invites", h.authn(h.createInvite))
	// Invite redemption is unauthenticated: the single-use token IS the
	// credential (same pattern as setup/login).
	mux.HandleFunc("POST /api/v1/invites/accept", h.acceptInvite)
	mux.Handle("GET /api/v1/organizations/{id}/members", h.authn(h.listOrganizationMembers))
	mux.Handle("POST /api/v1/users/{id}/disable", h.authn(h.disableUser))
	mux.Handle("POST /api/v1/users/{id}/enable", h.authn(h.enableUser))
	mux.Handle("POST /api/v1/users/{id}/admin", h.authn(h.setUserAdmin))
	mux.Handle("DELETE /api/v1/organizations/{id}", h.authn(h.deleteOrganization))
	mux.Handle("GET /api/v1/organizations/{id}/groups", h.authn(h.listGroups))
	mux.Handle("POST /api/v1/organizations/{id}/groups", h.authn(h.createGroup))
	mux.Handle("POST /api/v1/groups/{id}/members", h.authn(h.addGroupMember))
	mux.Handle("GET /api/v1/groups/{id}/members", h.authn(h.listGroupMembers))
	mux.Handle("POST /api/v1/users", h.authn(h.createUser))
	mux.Handle("GET /api/v1/users", h.authn(h.listUsers))
	mux.Handle("GET /api/v1/catalog", h.authn(h.listCatalog))
	mux.Handle("POST /api/v1/catalog", h.authn(h.registerCatalog))

	// G3 — domains.
	mux.Handle("POST /api/v1/organizations/{id}/domains", h.authn(h.createDomain))
	mux.Handle("GET /api/v1/organizations/{id}/domains", h.authn(h.listDomains))
	mux.Handle("POST /api/v1/domains/{id}/verify", h.authn(h.verifyDomain))
	mux.Handle("DELETE /api/v1/domains/{id}", h.authn(h.deleteDomain))
	mux.Handle("POST /api/v1/domains/{id}/hostnames", h.authn(h.addHostname))
	mux.Handle("GET /api/v1/domains/{id}/hostnames", h.authn(h.listHostnames))

	// G4 — mail.
	mux.Handle("POST /api/v1/domains/{id}/mail", h.authn(h.enableMail))
	mux.Handle("GET /api/v1/domains/{id}/mail", h.authn(h.mailStatus))
	mux.Handle("DELETE /api/v1/domains/{id}/mail", h.authn(h.disableMail))
	mux.Handle("POST /api/v1/domains/{id}/mail/reconcile", h.authn(h.reconcileMail))
	mux.Handle("POST /api/v1/domains/{id}/mail-identities", h.authn(h.createMailIdentity))
	mux.Handle("GET /api/v1/domains/{id}/mail-identities", h.authn(h.listMailIdentities))
	mux.Handle("POST /api/v1/mail-identities/{id}/credentials/rotate", h.authn(h.rotateMailCredential))
	mux.Handle("POST /api/v1/domains/{id}/mail/aliases", h.authn(h.createMailAlias))
	mux.Handle("GET /api/v1/domains/{id}/mail/aliases", h.authn(h.listMailAliases))

	mux.Handle("POST /api/v1/organizations/{id}/applications", h.authn(h.createApplication))
	mux.Handle("GET /api/v1/organizations/{id}/applications", h.authn(h.listApplications))

	// G7 — admin console (thin templates over the API, same OIDC session).
	mux.HandleFunc("GET /ui/setup", h.uiSetup)
	mux.HandleFunc("GET /", h.uiDashboard)
	mux.HandleFunc("GET /ui/orgs", h.uiOrgs)
	mux.HandleFunc("GET /ui/users", h.uiUsers)
	mux.HandleFunc("GET /ui/domains", h.uiDomains)
	mux.HandleFunc("GET /ui/mail", h.uiMail)
	mux.HandleFunc("GET /ui/catalog", h.uiCatalog)
	mux.HandleFunc("GET /ui/audit", h.uiAudit)

	var root http.Handler = mux
	root = secureHeaders(root)
	root = accessLog(d.Logger)(root)
	root = withRecoverer(d.Logger)(root)
	root = withRequestID(root)
	return root
}

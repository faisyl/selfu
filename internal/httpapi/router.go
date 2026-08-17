package httpapi

import "net/http"

// New assembles the full API router with middleware.
func New(d Deps) http.Handler {
	h := &Handler{d: d}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", h.health)
	mux.HandleFunc("GET /api/v1/auth/login", h.oidcLogin)
	mux.HandleFunc("GET /api/v1/auth/callback", h.oidcCallback)
	mux.Handle("GET /api/v1/me", h.requireAuth(h.me))

	// G2 — identity.
	mux.Handle("POST /api/v1/organizations", h.authn(h.createOrganization))
	mux.Handle("GET /api/v1/organizations", h.authn(h.listOrganizations))
	mux.Handle("POST /api/v1/organizations/{id}/members", h.authn(h.addOrganizationMember))
	mux.Handle("GET /api/v1/organizations/{id}/members", h.authn(h.listOrganizationMembers))
	mux.Handle("POST /api/v1/organizations/{id}/groups", h.authn(h.createGroup))
	mux.Handle("GET /api/v1/organizations/{id}/groups", h.authn(h.listGroups))
	mux.Handle("POST /api/v1/groups/{id}/members", h.authn(h.addGroupMember))
	mux.Handle("GET /api/v1/groups/{id}/members", h.authn(h.listGroupMembers))
	mux.Handle("POST /api/v1/users", h.authn(h.createUser))
	mux.Handle("GET /api/v1/users", h.authn(h.listUsers))
	mux.Handle("POST /api/v1/users/{id}/disable", h.authn(h.disableUser))

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

	var root http.Handler = mux
	root = accessLog(d.Logger)(root)
	root = withRecoverer(d.Logger)(root)
	root = withRequestID(root)
	return root
}

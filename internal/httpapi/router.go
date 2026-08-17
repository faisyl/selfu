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

	var root http.Handler = mux
	root = accessLog(d.Logger)(root)
	root = withRecoverer(d.Logger)(root)
	root = withRequestID(root)
	return root
}

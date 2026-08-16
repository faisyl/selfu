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

	var root http.Handler = mux
	root = accessLog(d.Logger)(root)
	root = withRecoverer(d.Logger)(root)
	root = withRequestID(root)
	return root
}

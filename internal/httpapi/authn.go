package httpapi

import (
	"context"
	"net/http"

	"selfu/internal/domain"
)

// The session-authentication module: one cookie → validate → fetch gateway
// used by every protected surface. It never writes a response; each route
// family (JSON 401, HTML 302) maps the outcome at its own seam.

// authenticate is the handler method: session gateway via the store adapter.
func (h *Handler) authenticate(r *http.Request) (domain.User, bool) {
	return h.currentSessionUser(r)
}

func (h *Handler) currentSessionUser(r *http.Request) (domain.User, bool) {
	c, err := r.Cookie(h.d.Sessions.CookieName())
	if err != nil {
		return domain.User{}, false
	}
	sess, err := h.d.Sessions.Validate(c.Value)
	if err != nil {
		return domain.User{}, false
	}
	u, err := h.d.Users.GetByID(r.Context(), sess.UserID)
	if err != nil {
		return domain.User{}, false
	}
	return u, true
}

// requireAuth gates a handler behind a valid session, returning 401 on
// failure (JSON route family).
func (h *Handler) requireAuth(next func(http.ResponseWriter, *http.Request, domain.User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := h.authenticate(r)
		if !ok {
			h.d.Sessions.ClearCookie(w)
			writeError(w, http.StatusUnauthorized, "unauthorized", "missing or invalid session")
			return
		}
		next(w, r, u)
	}
}

// authn authenticates and stores the user in the context for org-role
// authorization (spec §17); 401 on failure (JSON route family).
func (h *Handler) authn(next func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := h.authenticate(r)
		if !ok {
			h.d.Sessions.ClearCookie(w)
			writeError(w, http.StatusUnauthorized, "unauthorized", "missing or invalid session")
			return
		}
		next(w, withUserReq(r, u))
	}
}

// uiAuth gates an HTML page: unauthenticated browsers are redirected to the
// OIDC login (spec §15), never shown a 401 (HTML route family).
func (h *Handler) uiAuth(w http.ResponseWriter, r *http.Request) (domain.User, bool) {
	u, ok := h.authenticate(r)
	if ok {
		return u, true
	}
	http.Redirect(w, r, "/api/v1/auth/login", http.StatusFound)
	return domain.User{}, false
}

type userCtxKey struct{}

func withUserReq(r *http.Request, u domain.User) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), userCtxKey{}, u))
}

func rUser(r *http.Request) domain.User {
	u, _ := r.Context().Value(userCtxKey{}).(domain.User)
	return u
}

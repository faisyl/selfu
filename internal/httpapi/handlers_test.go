package httpapi

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"selfu/internal/auth"
	"selfu/internal/config"
	"selfu/internal/domain"
)

var errNotFound = errors.New("not found")

func storeErrNotFound() error { return errNotFound }

type fakeOIDC struct {
	identity auth.OIDCIdentity
	err      error
}

func (f *fakeOIDC) AuthCodeURL(state, nonce string) string {
	return "https://auth.example/authorize?state=" + state + "&nonce=" + nonce
}

func (f *fakeOIDC) Exchange(_ context.Context, _ string, _ string) (auth.OIDCIdentity, error) {
	return f.identity, f.err
}

type fakeUsers struct {
	byID map[string]domain.User
}

func (f *fakeUsers) UpsertFromOIDC(_ context.Context, _, _, email, display string) (domain.User, bool, bool, error) {
	u := domain.User{
		ID: "user-1", Email: email, DisplayName: display,
		Status: domain.UserStatusActive, IsAdmin: true,
	}
	f.byID[u.ID] = u
	return u, true, true, nil
}

func (f *fakeUsers) GetByID(_ context.Context, id string) (domain.User, error) {
	if u, ok := f.byID[id]; ok {
		return u, nil
	}
	return domain.User{}, storeErrNotFound()
}

type fakeAudit struct{ events []domain.AuditEvent }

func (f *fakeAudit) CreateAuditEvent(_ context.Context, e domain.AuditEvent) error {
	f.events = append(f.events, e)
	return nil
}

func (f *fakeAudit) ListAuditEvents(_ context.Context, _ int) ([]domain.AuditEvent, error) {
	return f.events, nil
}

func newHandler(t *testing.T, users *fakeUsers) (*Handler, *fakeAudit, *auth.SessionStore, *fakeOIDC) {
	t.Helper()
	sessions, err := auth.NewSessionStore(auth.SessionStoreOptions{
		Name:   "selfu_session",
		Secret: []byte(strings.Repeat("s", 32)),
		TTL:    time.Hour,
	})
	if err != nil {
		t.Fatalf("NewSessionStore: %v", err)
	}
	audit := &fakeAudit{}
	oidc := &fakeOIDC{identity: auth.OIDCIdentity{Subject: "sub-1", Email: "alice@example.com"}}
	h := &Handler{d: Deps{
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Sessions: sessions,
		OIDC:     oidc,
		Users:    users,
		Audit:    audit,
		OIDCConfig: config.OIDCConfig{
			Issuer: "https://auth.example",
		},
		AfterLoginPath: "/",
	}}
	return h, audit, sessions, oidc
}

func router(t *testing.T, h *Handler) http.Handler {
	t.Helper()
	return New(Deps{
		Logger:         h.d.Logger,
		Sessions:       h.d.Sessions,
		OIDC:           h.d.OIDC,
		Users:          h.d.Users,
		Audit:          h.d.Audit,
		OIDCConfig:     h.d.OIDCConfig,
		AfterLoginPath: h.d.AfterLoginPath,
		IdentityStore:  h.d.IdentityStore,
		Identity:       h.d.Identity,
		ProviderName:   h.d.ProviderName,
		DomainStore:    h.d.DomainStore,
		DNSProvider:    h.d.DNSProvider,
		TXTLookup:      h.d.TXTLookup,
	})
}

func TestHealth(t *testing.T) {
	users := &fakeUsers{byID: map[string]domain.User{}}
	h, _, _, _ := newHandler(t, users)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	w := httptest.NewRecorder()
	router(t, h).ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("health status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"ok"`) {
		t.Errorf("health body = %q, want ok status", w.Body.String())
	}
}

func TestMeUnauthenticated(t *testing.T) {
	users := &fakeUsers{byID: map[string]domain.User{}}
	h, _, _, _ := newHandler(t, users)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	router(t, h).ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("me without session status = %d, want 401", w.Code)
	}
}

func TestMeWithSession(t *testing.T) {
	users := &fakeUsers{byID: map[string]domain.User{
		"user-1": {ID: "user-1", Email: "alice@example.com", Status: domain.UserStatusActive},
	}}
	h, _, sessions, _ := newHandler(t, users)
	tok, err := sessions.Issue("user-1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	r.AddCookie(&http.Cookie{Name: sessions.CookieName(), Value: tok})
	w := httptest.NewRecorder()
	router(t, h).ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("me status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "alice@example.com") {
		t.Errorf("me body = %q, want email", w.Body.String())
	}
}

func TestLoginRedirectsToProvider(t *testing.T) {
	users := &fakeUsers{byID: map[string]domain.User{}}
	h, _, _, _ := newHandler(t, users)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/auth/login", nil)
	w := httptest.NewRecorder()
	router(t, h).ServeHTTP(w, r)
	if w.Code != http.StatusFound {
		t.Fatalf("login status = %d, want 302", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://auth.example/authorize?") {
		t.Errorf("Location = %q, want provider authorize URL", loc)
	}
	if !strings.Contains(w.Header().Get("Set-Cookie"), "selfu_oidc_state") {
		t.Error("missing oidc state cookie")
	}
}

func TestCallbackHappyPath(t *testing.T) {
	users := &fakeUsers{byID: map[string]domain.User{}}
	h, audit, sessions, _ := newHandler(t, users)
	rr := httptest.NewRecorder()
	if err := sessions.SetOIDCStateCookie(rr, auth.OIDCState{State: "st1", Nonce: "nn1"}); err != nil {
		t.Fatalf("SetOIDCStateCookie: %v", err)
	}
	cookies := rr.Result().Cookies()

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/auth/callback?code=abc&state=st1", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	router(t, h).ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("callback status = %d, want 302", w.Code)
	}
	if got := w.Header().Get("Location"); got != "/" {
		t.Errorf("Location = %q, want /", got)
	}

	foundSession := false
	for _, c := range w.Result().Cookies() {
		if c.Name == sessions.CookieName() && c.Value != "" {
			foundSession = true
		}
	}
	if !foundSession {
		t.Error("no session cookie set")
	}

	var actions []string
	for _, e := range audit.events {
		actions = append(actions, e.Action)
	}
	joined := strings.Join(actions, ",")
	if !strings.Contains(joined, "auth.login.succeeded") || !strings.Contains(joined, "user.admin_granted") {
		t.Errorf("audit actions = %v, want login.succeeded and admin_granted", actions)
	}
}

func TestCallbackStateMismatch(t *testing.T) {
	users := &fakeUsers{byID: map[string]domain.User{}}
	h, audit, sessions, _ := newHandler(t, users)
	rr := httptest.NewRecorder()
	if err := sessions.SetOIDCStateCookie(rr, auth.OIDCState{State: "st1", Nonce: "nn1"}); err != nil {
		t.Fatalf("SetOIDCStateCookie: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/callback?code=x&state=WRONG", nil)
	for _, c := range rr.Result().Cookies() {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	router(t, h).ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("mismatch status = %d, want 400", w.Code)
	}
	if len(audit.events) != 1 || audit.events[0].Action != "auth.oidc.failed" {
		t.Errorf("audit events = %+v, want single auth.oidc.failed", audit.events)
	}
}

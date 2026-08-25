package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"selfu/internal/access"
	"selfu/internal/dns"
	"selfu/internal/domain"
	"selfu/internal/store"
)

// fakeIdentityStore is the minimal IdentityStore surface used by the setup
// wizard tests: organization creation and ownership membership.
type fakeIdentityStore struct {
	orgs     map[string]domain.Organization
	members  map[string]domain.OrganizationMembership
	statuses map[string]domain.UserStatus
	nextID   int
}

func (f *fakeIdentityStore) CreateOrganization(_ context.Context, o domain.Organization) (domain.Organization, error) {
	if f.orgs == nil {
		f.orgs = map[string]domain.Organization{}
	}
	for _, existing := range f.orgs {
		if existing.Slug == o.Slug {
			return domain.Organization{}, store.ErrConflict
		}
	}
	f.nextID++
	o.ID = "org-" + string(rune('0'+f.nextID))
	f.orgs[o.ID] = o
	return o, nil
}

func (f *fakeIdentityStore) SetMembership(_ context.Context, orgID, userID string, role domain.OrgRole) (domain.OrganizationMembership, error) {
	m := domain.OrganizationMembership{OrganizationID: orgID, UserID: userID, Role: role}
	if f.members == nil {
		f.members = map[string]domain.OrganizationMembership{}
	}
	f.members[orgID+"|"+userID] = m
	return m, nil
}

func (f *fakeIdentityStore) GetMembershipRole(_ context.Context, orgID, userID string) (domain.OrgRole, error) {
	if m, ok := f.members[orgID+"|"+userID]; ok {
		return m.Role, nil
	}
	return "", store.ErrNotFound
}

func (f *fakeIdentityStore) ListOrganizations(_ context.Context, _ int) ([]domain.Organization, error) {
	var out []domain.Organization
	for _, o := range f.orgs {
		out = append(out, o)
	}
	return out, nil
}

func (f *fakeIdentityStore) GetOrganizationByID(_ context.Context, _ string) (domain.Organization, error) {
	return domain.Organization{}, store.ErrNotFound
}
func (f *fakeIdentityStore) DeleteOrganization(context.Context, string) error { return nil }
func (f *fakeIdentityStore) ListMemberships(context.Context, string) ([]store.Member, error) {
	return nil, nil
}
func (f *fakeIdentityStore) RemoveMembership(context.Context, string, string) error { return nil }
func (f *fakeIdentityStore) RemoveAllMemberships(context.Context, string) error     { return nil }
func (f *fakeIdentityStore) CreateGroup(context.Context, domain.Group) (domain.Group, error) {
	return domain.Group{}, store.ErrNotFound
}
func (f *fakeIdentityStore) GetGroupByID(context.Context, string) (domain.Group, error) {
	return domain.Group{}, store.ErrNotFound
}
func (f *fakeIdentityStore) ListGroupsByOrg(context.Context, string) ([]domain.Group, error) {
	return nil, nil
}
func (f *fakeIdentityStore) DeleteGroup(context.Context, string) error            { return nil }
func (f *fakeIdentityStore) AddGroupMember(context.Context, string, string) error { return nil }
func (f *fakeIdentityStore) RemoveGroupMember(context.Context, string, string) error {
	return nil
}
func (f *fakeIdentityStore) RemoveAllGroupMemberships(context.Context, string) error { return nil }
func (f *fakeIdentityStore) ListGroupMembers(context.Context, string) ([]store.GroupMember, error) {
	return nil, nil
}
func (f *fakeIdentityStore) GetUserByEmail(context.Context, string) (domain.User, error) {
	return domain.User{}, store.ErrNotFound
}
func (f *fakeIdentityStore) CreateUser(context.Context, string, string, string, string) (domain.User, error) {
	return domain.User{}, store.ErrNotFound
}

func (f *fakeIdentityStore) SetUserStatus(_ context.Context, id string, status domain.UserStatus) error {
	if f.statuses == nil {
		f.statuses = map[string]domain.UserStatus{}
	}
	f.statuses[id] = status
	return nil
}

func (f *fakeIdentityStore) SetUserAdmin(context.Context, string, bool) error      { return nil }
func (f *fakeIdentityStore) ListUsers(context.Context, int) ([]domain.User, error) { return nil, nil }
func (f *fakeIdentityStore) UpsertExternalResource(context.Context, domain.ExternalResource) (domain.ExternalResource, error) {
	return domain.ExternalResource{}, nil
}
func (f *fakeIdentityStore) GetExternalResource(context.Context, string, string) (domain.ExternalResource, error) {
	return domain.ExternalResource{}, store.ErrNotFound
}
func (f *fakeIdentityStore) SetExternalStatus(context.Context, string, string, string) error {
	return nil
}

func setupHandler(t *testing.T, onboarded bool, txts []string) (*Handler, *fakeSetup, *fakeDomainStore, *fakeIdentityStore) {
	t.Helper()
	users := &fakeUsers{byID: map[string]domain.User{
		"user-1": {ID: "user-1", Email: "admin@selfu.local", Status: domain.UserStatusActive, IsAdmin: true},
	}}
	h, audit, sessions, _ := newHandler(t, users)
	setup := &fakeSetup{}
	if onboarded {
		now := time.Now().UTC()
		setup.onboardedAt = &now
	}
	h.d.Setup = setup
	h.d.TXTLookup = func(context.Context, string) ([]string, error) { return txts, nil }
	domainStore := &fakeDomainStore{domains: map[string]domain.Domain{}}
	h.d.DomainStore = domainStore
	idStore := &fakeIdentityStore{}
	h.d.IdentityStore = idStore
	_ = audit
	_ = sessions
	return h, setup, domainStore, idStore
}

func TestSetupStatusPublic(t *testing.T) {
	h, _, _, _ := setupHandler(t, false, nil)
	w := httptest.NewRecorder()
	router(t, h).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/setup", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("setup status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, `"onboarded":false`) {
		t.Errorf("body = %s, want onboarded:false", body)
	}
	if !strings.Contains(body, "selfu.local") {
		t.Errorf("body = %s, want local domain", body)
	}
}

func TestCreateSetupNonAdminForbidden(t *testing.T) {
	users := &fakeUsers{byID: map[string]domain.User{
		"user-member": {ID: "user-member", Email: "bob@acme.example", Status: domain.UserStatusActive},
	}}
	h, _, sessions, _ := newHandler(t, users)
	tok, _ := sessions.Issue("user-member")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/setup",
		strings.NewReader(`{"fqdn":"example.com","provider":"manual"}`))
	req.AddCookie(&http.Cookie{Name: sessions.CookieName(), Value: tok})
	w := httptest.NewRecorder()
	router(t, h).ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("setup as non-admin = %d, want 403", w.Code)
	}
}

func TestCreateSetupHappyPath(t *testing.T) {
	h, setup, domainStore, _ := setupHandler(t, false, nil)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/setup",
		strings.NewReader(`{"fqdn":"example.com","provider":"manual"}`))
	req.AddCookie(&http.Cookie{Name: h.d.Sessions.CookieName(), Value: mustIssue(t, h)})
	router(t, h).ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("setup = %d, want 201: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, `"automated":false`) || !strings.Contains(body, "_platform-verification.example.com") {
		t.Errorf("body = %s, want manual verification record", body)
	}
	if setup.primaryID == "" {
		t.Error("primary domain not associated")
	}
	if len(domainStore.domains) != 1 {
		t.Fatalf("domains stored = %d, want 1", len(domainStore.domains))
	}
	if setup.onboardedAt != nil {
		t.Error("must not be onboarded before verification")
	}
}

func TestCreateSetupAlreadyOnboarded(t *testing.T) {
	h, _, _, _ := setupHandler(t, true, nil)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/setup",
		strings.NewReader(`{"fqdn":"example.com","provider":"manual"}`))
	req.AddCookie(&http.Cookie{Name: h.d.Sessions.CookieName(), Value: mustIssue(t, h)})
	router(t, h).ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("setup when onboarded = %d, want 409", w.Code)
	}
}

func TestCreateSetupUnknownProvider(t *testing.T) {
	h, _, _, _ := setupHandler(t, false, nil)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/setup",
		strings.NewReader(`{"fqdn":"example.com","provider":"nope"}`))
	req.AddCookie(&http.Cookie{Name: h.d.Sessions.CookieName(), Value: mustIssue(t, h)})
	router(t, h).ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unknown provider = %d, want 400", w.Code)
	}
}

func TestCreateSetupCloudflareMissingToken(t *testing.T) {
	h, _, domainStore, _ := setupHandler(t, false, nil)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/setup",
		strings.NewReader(`{"fqdn":"example.com","provider":"cloudflare"}`)) // no api_token
	req.AddCookie(&http.Cookie{Name: h.d.Sessions.CookieName(), Value: mustIssue(t, h)})
	router(t, h).ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("cloudflare without token = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "api_token") {
		t.Errorf("body = %s, want message naming api_token", w.Body.String())
	}
	// No domain may exist (must fail before provisioning).
	if len(domainStore.domains) != 0 {
		t.Errorf("domains created = %d, want 0", len(domainStore.domains))
	}
}

func TestCreateSetupCloudflareAutoZone(t *testing.T) {
	h, setup, domainStore, _ := setupHandler(t, false, nil)
	var resolvedDomain, resolvedToken string
	var probedName string
	h.d.ZoneResolver = func(_ context.Context, domain, apiToken string) (string, error) {
		resolvedDomain, resolvedToken = domain, apiToken
		return "auto-zone-123", nil
	}
	h.d.ProviderProbe = func(_ context.Context, p access.Provider) error {
		probedName = p.Name()
		return nil
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/setup",
		strings.NewReader(`{"fqdn":"example.com","provider":"cloudflare","api_token":"tok"}`)) // no zone_id
	req.AddCookie(&http.Cookie{Name: h.d.Sessions.CookieName(), Value: mustIssue(t, h)})
	router(t, h).ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("auto-zone setup = %d, want 201: %s", w.Code, w.Body.String())
	}
	if resolvedDomain != "example.com" || resolvedToken != "tok" {
		t.Errorf("resolver got domain=%q token=%q, want example.com/tok", resolvedDomain, resolvedToken)
	}
	if probedName != "cloudflare" {
		t.Errorf("probe not called with cloudflare provider (got %q)", probedName)
	}
	if setup.config == nil {
		t.Error("provider config not stored")
	}
	if len(domainStore.domains) != 1 {
		t.Fatalf("domains stored = %d, want 1", len(domainStore.domains))
	}
}

func TestVerifySetupOnboards(t *testing.T) {
	h, setup, domainStore, _ := setupHandler(t, false, nil)
	if err := h.d.Setup.SetInstallationPrimaryDomain(context.Background(), "dom-1"); err != nil {
		t.Fatalf("SetInstallationPrimaryDomain: %v", err)
	}
	domainStore.domains["dom-1"] = domain.Domain{
		ID: "dom-1", OrganizationID: "org-1", FQDN: "example.com",
		Status: domain.DomainPending, VerificationMethod: "dns_txt",
		VerificationToken: "tok1",
	}
	// TXT lookup returns the token value.
	h.d.TXTLookup = func(_ context.Context, name string) ([]string, error) {
		if name != dns.VerifyRecordName("example.com") {
			t.Errorf("lookup name = %s", name)
		}
		return []string{dns.TokenTXTValue("tok1")}, nil
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/setup/verify", nil)
	req.AddCookie(&http.Cookie{Name: h.d.Sessions.CookieName(), Value: mustIssue(t, h)})
	router(t, h).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("verify = %d, want 200: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"onboarded":true`) {
		t.Errorf("body = %s, want onboarded:true", w.Body.String())
	}
	if setup.onboardedAt == nil {
		t.Error("installation not marked onboarded")
	}
}

func TestVerifySetupNotReady(t *testing.T) {
	h, setup, domainStore, _ := setupHandler(t, false, nil)
	if err := h.d.Setup.SetInstallationPrimaryDomain(context.Background(), "dom-1"); err != nil {
		t.Fatalf("SetInstallationPrimaryDomain: %v", err)
	}
	domainStore.domains["dom-1"] = domain.Domain{
		ID: "dom-1", OrganizationID: "org-1", FQDN: "example.com",
		Status: domain.DomainPending, VerificationMethod: "dns_txt",
		VerificationToken: "tok1",
	}
	h.d.TXTLookup = func(context.Context, string) ([]string, error) { return nil, nil }
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/setup/verify", nil)
	req.AddCookie(&http.Cookie{Name: h.d.Sessions.CookieName(), Value: mustIssue(t, h)})
	router(t, h).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("verify = %d, want 200", w.Code)
	}
	if strings.Contains(w.Body.String(), `"onboarded":true`) {
		t.Error("must not be onboarded before TXT present")
	}
	if setup.onboardedAt != nil {
		t.Error("installation marked onboarded too early")
	}
}

func TestSetupLoginHappyPath(t *testing.T) {
	h, setup, _, _ := setupHandler(t, false, nil)
	h.d.BootstrapPassword = "s3cret"
	h.d.BootstrapEmail = "admin@selfu.local"

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/setup/login",
		strings.NewReader(`{"password":"s3cret"}`))
	router(t, h).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("login status = %d, want 200: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"ok":true`) {
		t.Errorf("body = %s, want ok:true", w.Body.String())
	}
	// Session cookie must be issued.
	found := false
	for _, c := range w.Result().Cookies() {
		if c.Name == h.d.Sessions.CookieName() && c.Value != "" {
			found = true
		}
	}
	if !found {
		t.Error("no session cookie set after bootstrap login")
	}
	_ = setup
}

func TestSetupLoginWrongPassword(t *testing.T) {
	h, _, _, _ := setupHandler(t, false, nil)
	h.d.BootstrapPassword = "s3cret"
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/setup/login",
		strings.NewReader(`{"password":"wrong"}`))
	router(t, h).ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password status = %d, want 401", w.Code)
	}
}

func TestSetupLoginDisabledAfterOnboard(t *testing.T) {
	h, _, _, _ := setupHandler(t, true, nil) // onboarded
	h.d.BootstrapPassword = "s3cret"
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/setup/login",
		strings.NewReader(`{"password":"s3cret"}`))
	router(t, h).ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("login after onboard status = %d, want 403", w.Code)
	}
}

func TestSetupLoginNotConfigured(t *testing.T) {
	h, _, _, _ := setupHandler(t, false, nil) // BootstrapPassword empty
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/setup/login",
		strings.NewReader(`{"password":"x"}`))
	router(t, h).ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured login status = %d, want 503", w.Code)
	}
}

// mustIssue issues a session token for the admin fixture.
func mustIssue(t *testing.T, h *Handler) string {
	t.Helper()
	tok, err := h.d.Sessions.Issue("user-1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return tok
}

func TestSetupLoginRateLimited(t *testing.T) {
	h, _, _, _ := setupHandler(t, false, nil)
	h.d.BootstrapPassword = "s3cret"
	bootstrapLimiter.reset("test-ip")
	t.Cleanup(func() { bootstrapLimiter.reset("test-ip") })

	post := func() int {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/setup/login",
			strings.NewReader(`{"password":"wrong"}`))
		req.Header.Set("X-Forwarded-For", "test-ip")
		router(t, h).ServeHTTP(w, req)
		return w.Code
	}
	for i := 0; i < loginMaxFails; i++ {
		if c := post(); c != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d, want 401", i+1, c)
		}
	}
	if c := post(); c != http.StatusTooManyRequests {
		t.Fatalf("post-limit status = %d, want 429", c)
	}
}

func TestSetupStatusIncludesPendingDomain(t *testing.T) {
	h, _, domainStore, _ := setupHandler(t, false, nil)
	domainStore.domains["dom-1"] = domain.Domain{
		ID: "dom-1", OrganizationID: "org-1", FQDN: "example.com",
		Status: domain.DomainPending,
	}
	if err := h.d.Setup.SetInstallationPrimaryDomain(context.Background(), "dom-1"); err != nil {
		t.Fatalf("SetInstallationPrimaryDomain: %v", err)
	}
	w := httptest.NewRecorder()
	router(t, h).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/setup", nil))
	body := w.Body.String()
	if !strings.Contains(body, `"primary_domain"`) || !strings.Contains(body, `"pending"`) || !strings.Contains(body, `"provider":"manual"`) {
		t.Errorf("body = %s, want pending primary domain info", body)
	}
}

func TestLogoutClearsSession(t *testing.T) {
	users := &fakeUsers{byID: map[string]domain.User{
		"user-1": {ID: "user-1", Email: "a@x.test", Status: domain.UserStatusActive, IsAdmin: true},
	}}
	h, _, sessions, _ := newHandler(t, users)
	tok, _ := sessions.Issue("user-1")

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: sessions.CookieName(), Value: tok})
	router(t, h).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("logout = %d, want 200", w.Code)
	}
	var clear *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == sessions.CookieName() && c.Value == "" {
			clear = c
		}
	}
	if clear == nil || clear.MaxAge > 0 {
		t.Error("logout did not expire the session cookie")
	}
}

func TestSetUserAdminGuards(t *testing.T) {
	users := &fakeUsers{byID: map[string]domain.User{
		"user-a": {ID: "user-a", Email: "a@x.test", Status: domain.UserStatusActive, IsAdmin: true},
		"user-b": {ID: "user-b", Email: "b@x.test", Status: domain.UserStatusActive, IsAdmin: true},
		"user-c": {ID: "user-c", Email: "c@x.test", Status: domain.UserStatusActive, IsAdmin: true},
	}}
	h, _, sessions, _ := newHandler(t, users)
	h.d.IdentityStore = &fakeIdentityStore{}

	post := func(target string, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/users/"+target+"/admin",
			strings.NewReader(body))
		tok, _ := sessions.Issue("user-a")
		req.AddCookie(&http.Cookie{Name: sessions.CookieName(), Value: tok})
		router(t, h).ServeHTTP(w, req)
		return w
	}
	setAdmin := func(id string, v bool) {
		u := users.byID[id]
		u.IsAdmin = v
		users.byID[id] = u
	}

	// Self-demotion forbidden.
	if w := post("user-a", `{"admin":false}`); w.Code != http.StatusBadRequest {
		t.Errorf("self-demote = %d, want 400", w.Code)
	}
	// Demoting other admins OK while more than one remains.
	if w := post("user-b", `{"admin":false}`); w.Code != http.StatusOK {
		t.Fatalf("demote user-b = %d, want 200", w.Code)
	}
	setAdmin("user-b", false)
	if w := post("user-c", `{"admin":false}`); w.Code != http.StatusOK {
		t.Fatalf("demote user-c = %d, want 200", w.Code)
	}
	setAdmin("user-c", false)
	// Only the requester remains; demoting anyone else trips the guard.
	if w := post("user-b", `{"admin":false}`); w.Code != http.StatusConflict {
		t.Errorf("last-admin guard = %d, want 409", w.Code)
	}
}

func TestEnableUserReactivates(t *testing.T) {
	idStore := &fakeIdentityStore{statuses: map[string]domain.UserStatus{
		"user-x": domain.UserStatusDisabled,
	}}
	users := &fakeUsers{byID: map[string]domain.User{
		"user-a": {ID: "user-a", Email: "a@x.test", Status: domain.UserStatusActive, IsAdmin: true},
	}}
	h, _, sessions, _ := newHandler(t, users)
	h.d.IdentityStore = idStore

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/user-x/enable", nil)
	tok, _ := sessions.Issue("user-a")
	req.AddCookie(&http.Cookie{Name: sessions.CookieName(), Value: tok})
	router(t, h).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("enable = %d, want 200", w.Code)
	}
	if got := idStore.statuses["user-x"]; got != domain.UserStatusActive {
		t.Errorf("status = %q, want active", got)
	}
}

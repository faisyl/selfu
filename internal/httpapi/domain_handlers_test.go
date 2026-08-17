package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"selfu/internal/domain"
	"selfu/internal/store"
)

// fakeDomainStore is an in-memory DomainStore for handler tests.
type fakeDomainStore struct {
	domains      map[string]domain.Domain
	hostnames    map[string]domain.Hostname
	apiInstances map[string][]string
	verifs       []string
}

func (f *fakeDomainStore) CreateDomain(_ context.Context, d domain.Domain) (domain.Domain, error) {
	d.ID = d.ID + "-new" // marker for tests
	d.Status = domain.DomainPending
	d.VerificationToken = "tok123"
	if f.domains == nil {
		f.domains = map[string]domain.Domain{}
	}
	f.domains[d.ID] = d
	return d, nil
}
func (f *fakeDomainStore) GetDomainByID(_ context.Context, id string) (domain.Domain, error) {
	if d, ok := f.domains[id]; ok {
		d.ID = id
		return d, nil
	}
	return domain.Domain{}, store.ErrNotFound
}
func (f *fakeDomainStore) GetDomainByOrgFQDN(_ context.Context, _, _ string) (domain.Domain, error) {
	return domain.Domain{}, store.ErrNotFound
}
func (f *fakeDomainStore) ListDomainsByOrg(_ context.Context, _ string) ([]domain.Domain, error) {
	var out []domain.Domain
	for _, d := range f.domains {
		out = append(out, d)
	}
	return out, nil
}
func (f *fakeDomainStore) SetDomainStatus(_ context.Context, id string, status domain.DomainStatus, vt *time.Time) error {
	if d, ok := f.domains[id]; ok {
		d.Status = status
		d.VerifiedAt = vt
		f.domains[id] = d
		return nil
	}
	return store.ErrNotFound
}
func (f *fakeDomainStore) LogVerification(_ context.Context, _ string, _ string, _ string, _ bool) error {
	return nil
}
func (f *fakeDomainStore) DeleteDomain(_ context.Context, id string) error {
	for _, h := range f.hostnames {
		if h.DomainID == id {
			return store.ErrHasDependents
		}
	}
	delete(f.domains, id)
	return nil
}
func (f *fakeDomainStore) AddHostname(_ context.Context, h domain.Hostname) (domain.Hostname, error) {
	if f.hostnames == nil {
		f.hostnames = map[string]domain.Hostname{}
	}
	h.ID = "host-1"
	h.Status = "active"
	f.hostnames[h.ID] = h
	return h, nil
}
func (f *fakeDomainStore) GetHostnameByID(_ context.Context, _ string) (domain.Hostname, error) {
	return domain.Hostname{}, store.ErrNotFound
}
func (f *fakeDomainStore) ListHostnamesByDomain(_ context.Context, domainID string) ([]domain.Hostname, error) {
	var out []domain.Hostname
	for _, h := range f.hostnames {
		if h.DomainID == domainID {
			out = append(out, h)
		}
	}
	return out, nil
}
func (f *fakeDomainStore) RemoveHostname(_ context.Context, _ string) error { return nil }

// TestVerifyThenBindHostname covers the positive path: a domain whose TXT
// record is present verifies, then a contained hostname binds, and deletion
// is refused while the hostname depends on it (spec §64).
func TestVerifyThenBindHostname(t *testing.T) {
	store := &fakeDomainStore{domains: map[string]domain.Domain{
		"dom-1": {ID: "dom-1", OrganizationID: "org-1", FQDN: "example.com",
			Status: domain.DomainPending, VerificationToken: "tok123"},
	}}
	users := &fakeUsers{byID: map[string]domain.User{
		"user-admin": {ID: "user-admin", Email: "a@x.test", Status: domain.UserStatusActive, IsAdmin: true},
	}}
	h, _, sessions, _ := newHandler(t, users)
	h.d.DomainStore = store
	h.d.TXTLookup = func(_ context.Context, _ string) ([]string, error) {
		return []string{"platform=tok123"}, nil
	}
	// Platform admins bypass org checks, so the org member gate passes.

	tok, _ := sessions.Issue("user-admin")

	do := func(req *http.Request, cookie string) *httptest.ResponseRecorder {
		req.AddCookie(&http.Cookie{Name: sessions.CookieName(), Value: tok})
		w := httptest.NewRecorder()
		router(t, h).ServeHTTP(w, req)
		return w
	}

	w := do(httptest.NewRequest(http.MethodPost, "/api/v1/domains/dom-1/verify", nil), "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "verified") {
		t.Fatalf("verify status = %d body=%s, want 200 verified", w.Code, w.Body.String())
	}
	if store.domains["dom-1"].Status != domain.DomainVerified {
		t.Errorf("domain status = %q, want verified", store.domains["dom-1"].Status)
	}

	// Bind a contained hostname.
	w = do(httptest.NewRequest(http.MethodPost, "/api/v1/domains/dom-1/hostnames",
		strings.NewReader(`{"hostname":"git.example.com"}`)), "")
	if w.Code != http.StatusCreated {
		t.Fatalf("add hostname status = %d body=%s, want 201", w.Code, w.Body.String())
	}

	// Out-of-domain hostname rejected.
	w = do(httptest.NewRequest(http.MethodPost, "/api/v1/domains/dom-1/hostnames",
		strings.NewReader(`{"hostname":"notexample.com"}`)), "")
	if w.Code != http.StatusBadRequest {
		t.Errorf("out-of-domain hostname status = %d, want 400", w.Code)
	}

	// Delete refused while hostname depends on it.
	w = do(httptest.NewRequest(http.MethodDelete, "/api/v1/domains/dom-1", nil), "")
	if w.Code != http.StatusConflict {
		t.Errorf("delete with dependents status = %d, want 409", w.Code)
	}
}

package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"selfu/internal/domain"
	"selfu/internal/dns"
)

// createPendingPrimary drives the wizard create endpoint so a pending
// primary domain exists (same path as production).
func createPendingPrimary(t *testing.T, h *Handler) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/setup",
		strings.NewReader(`{"fqdn":"example.com","provider":"manual"}`))
	req.AddCookie(&http.Cookie{Name: h.d.Sessions.CookieName(), Value: mustIssue(t, h)})
	w := httptest.NewRecorder()
	router(t, h).ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("setup create = %d, want 201: %s", w.Code, w.Body.String())
	}
}

// pollHandler wires a handler for auto-verify poller tests and returns
// the fakes the assertions need.
func pollHandler(t *testing.T) (*Handler, *fakeSetup, *fakeDomainStore, *fakeAudit) {
	t.Helper()
	users := &fakeUsers{byID: map[string]domain.User{
		"user-1": {ID: "user-1", Email: "admin@selfu.local", Status: domain.UserStatusActive, IsAdmin: true},
	}}
	h, audit, _, _ := newHandler(t, users)
	setup := &fakeSetup{}
	h.d.Setup = setup
	ds := &fakeDomainStore{domains: map[string]domain.Domain{}}
	h.d.DomainStore = ds
	h.d.IdentityStore = &fakeIdentityStore{}
	return h, setup, ds, audit
}

func pendingDomain(domainStore *fakeDomainStore) domain.Domain {
	for _, d := range domainStore.domains {
		return d
	}
	return domain.Domain{}
}

func TestPollVerifiesAndOnboards(t *testing.T) {
	h, setup, ds, audit := pollHandler(t)
	createPendingPrimary(t, h)
	dom := pendingDomain(ds)
	if dom.VerificationToken == "" {
		t.Fatal("pending primary domain has no verification token")
	}
	value := dns.TokenTXTValue(dom.VerificationToken)
	h.d.TXTLookup = func(context.Context, string) ([]string, error) {
		return []string{value}, nil
	}

	done := h.pollVerificationOnce(context.Background())
	if !done {
		t.Error("poll should signal the loop to stop once onboarded")
	}
	if setup.onboardedAt == nil {
		t.Error("installation was not marked onboarded")
	}
	stored, err := ds.GetDomainByID(context.Background(), dom.ID)
	if err != nil {
		t.Fatalf("get domain: %v", err)
	}
	if stored.Status != domain.DomainVerified {
		t.Errorf("domain status = %q, want verified", stored.Status)
	}
	foundAudit := false
	for _, e := range audit.events {
		if e.Action == "setup.onboarded" {
			foundAudit = true
		}
	}
	if !foundAudit {
		t.Error("expected setup.onboarded audit event from the poller")
	}
}

func TestPollNoOpsWithoutMatchingTXT(t *testing.T) {
	h, setup, ds, _ := pollHandler(t)
	createPendingPrimary(t, h)

	h.d.TXTLookup = func(context.Context, string) ([]string, error) {
		return []string{"platform=not-the-token"}, nil
	}

	done := h.pollVerificationOnce(context.Background())
	if done {
		t.Error("poll must not stop while verification is still pending")
	}
	if setup.onboardedAt != nil {
		t.Error("installation must not be onboarded without a matching TXT")
	}
	for _, d := range ds.domains {
		if d.Status == domain.DomainVerified {
			t.Errorf("domain %s unexpectedly verified", d.ID)
		}
	}
	lc, res := h.verifySnapshot()
	if lc.IsZero() || res == "" {
		t.Errorf("last check not recorded: %v %q", lc, res)
	}
}

func TestPollIdempotentOnceOnboarded(t *testing.T) {
	h, _, _, _ := setupHandler(t, true, nil)
	called := false
	h.d.TXTLookup = func(context.Context, string) ([]string, error) {
		called = true
		return nil, nil
	}

	done := h.pollVerificationOnce(context.Background())
	if !done {
		t.Error("poll should report completion when already onboarded")
	}
	if called {
		t.Error("TXT lookup must not run once onboarded")
	}
}

func TestSetupStatusSurfacesAutoVerify(t *testing.T) {
	h, _, _, _ := pollHandler(t)
	createPendingPrimary(t, h)
	h.d.TXTLookup = func(context.Context, string) ([]string, error) {
		return []string{"platform=nope"}, nil
	}
	h.pollVerificationOnce(context.Background())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/setup", nil)
	req.AddCookie(&http.Cookie{Name: h.d.Sessions.CookieName(), Value: mustIssue(t, h)})
	w := httptest.NewRecorder()
	h.BuildRouter().ServeHTTP(w, req) // same instance: carries poller state
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	av, ok := body["auto_verify"].(map[string]any)
	if !ok {
		t.Fatalf("body = %s, want auto_verify block", w.Body.String())
	}
	if av["last_check"] == nil || av["last_result"] == "" {
		t.Errorf("auto_verify = %+v, want last_check + last_result", av)
	}
	pd, ok := body["primary_domain"].(map[string]any)
	if !ok || pd["status"] != string(domain.DomainPending) {
		t.Errorf("primary_domain = %+v, want pending status", body["primary_domain"])
	}
}

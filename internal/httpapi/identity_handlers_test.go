package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"selfu/internal/domain"
)

// TestCreateOrganizationNonAdminForbidden verifies authorization default-
// deny: a non-admin cannot create an organization (spec §17 default deny).
func TestCreateOrganizationNonAdminForbidden(t *testing.T) {
	member := domain.User{
		ID: "user-member", Email: "bob@acme.example", DisplayName: "Bob",
		Status: domain.UserStatusActive, IsAdmin: false,
	}
	users := &fakeUsers{byID: map[string]domain.User{member.ID: member}}
	h, _, sessions, _ := newHandler(t, users)

	tok, err := sessions.Issue(member.ID)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/organizations",
		strings.NewReader(`{"name":"Blocked"}`))
	req.AddCookie(&http.Cookie{Name: sessions.CookieName(), Value: tok})
	w := httptest.NewRecorder()
	router(t, h).ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("create organization as non-admin status = %d, want 403", w.Code)
	}
}

// TestAuthnNoSessionUnauthorized verifies an authenticated-route without a
// session yields 401.
func TestAuthnNoSessionUnauthorized(t *testing.T) {
	h, _, _, _ := newHandler(t, &fakeUsers{byID: map[string]domain.User{}})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/organizations",
		strings.NewReader(`{"name":"X"}`))
	w := httptest.NewRecorder()
	router(t, h).ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("identity route without session status = %d, want 401", w.Code)
	}
}

func TestOrgRoleRanking(t *testing.T) {
	cases := []struct {
		role, required domain.OrgRole
		want           bool
	}{
		{domain.RoleOwner, domain.RoleOwner, true},
		{domain.RoleOwner, domain.RoleAdmin, true},
		{domain.RoleAdmin, domain.RoleOwner, false},
		{domain.RoleAdmin, domain.RoleAdmin, true},
		{domain.RoleMember, domain.RoleAdmin, false},
		{domain.RoleMember, domain.RoleMember, true},
	}
	for _, c := range cases {
		if got := c.role.CanManage(c.required); got != c.want {
			t.Errorf("CanManage(%s,%s)=%v, want %v", c.role, c.required, got, c.want)
		}
	}
}

func TestSlugify(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Acme Corp", "acme-corp"},
		{"  Gitea  ", "gitea"},
		{"Dev Team!", "dev-team"},
		{"", "org"},
	}
	for _, c := range cases {
		if got := domain.Slugify(c.in); got != c.want {
			t.Errorf("Slugify(%q)=%q, want %q", c.in, got, c.want)
		}
	}
}

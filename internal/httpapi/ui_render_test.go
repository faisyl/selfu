package httpapi

import (
	"bytes"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"selfu/internal/domain"
	"selfu/internal/store"
)

// Render smoke test: execute EVERY page template with representative sample
// data and assert no error. Template crashes (e.g. mail.html once read a
// MailDomain.GroupID field that only exists on MailAlias) surface here even
// when API-level acceptance passes, because the API never renders HTML.
//
// When a new page template is added to web/, add it here too — the set check
// below fails until the page has representative render coverage.

var sampleUser = domain.User{
	ID:          "user-1",
	Email:       "alice@example.com",
	DisplayName: "Alice",
	Status:      domain.UserStatusActive,
	IsAdmin:     true,
}

func sampleOrgs() []domain.Organization {
	return []domain.Organization{{
		ID: "org-1", Name: "Acme", Slug: "acme", Status: "active",
		CreatedAt: time.Unix(1700000000, 0), UpdatedAt: time.Unix(1700000000, 0),
	}}
}

func sampleBase(active, title string) uiBase {
	return uiBase{User: sampleUser, Active: active, Title: title}
}

func groupBoundAlias() domain.MailAlias {
	gid := "group-1"
	return domain.MailAlias{
		ID:             "alias-2",
		OrganizationID: "org-1",
		DomainID:       "dom-1",
		GroupID:        &gid,
		LocalPart:      "developers",
		Address:        "developers@pruxi.in",
		Destinations:   []string{"alice@pruxi.in", "bob@pruxi.in"},
		Status:         "active",
	}
}

// sampleMailData returns the mail view-model with mail ENABLED and both a
// plain alias and a §42 group-bound alias.
func sampleMailData() uiMailData {
	md := &domain.MailDomain{
		ID: "md-1", DomainID: "dom-1", Status: domain.MailDomainActive,
		Inbound: "ok", Outbound: "ok", TLS: "ok", DKIM: "ok",
		CreatedAt: time.Unix(1700000000, 0), UpdatedAt: time.Unix(1700000000, 0),
	}
	return uiMailData{
		uiBase:     sampleBase("mail", "Mail"),
		Orgs:       sampleOrgs(),
		OrgID:      "org-1",
		DomainID:   "dom-1",
		FQDN:       "pruxi.in",
		MailDomain: md,
		Identities: []domain.MailIdentity{{
			ID: "mi-1", OrganizationID: "org-1", DomainID: "dom-1",
			LocalPart: "alice", Address: "alice@pruxi.in",
			ChasquidUsername: "alice_pruxi.in", Status: domain.MailIdentityActive,
		}},
		Aliases: []domain.MailAlias{
			{
				ID: "alias-1", OrganizationID: "org-1", DomainID: "dom-1",
				LocalPart: "support", Address: "support@pruxi.in",
				Destinations: []string{"alice@pruxi.in"}, Status: "active",
			},
			groupBoundAlias(),
		},
		// What uiMail resolves for the §42 group-bound alias.
		AliasGroups: map[string]string{"alias-2": "developers"},
	}
}

// pageSamples maps every content template name to representative data.
func pageSamples() map[string]any {
	return map[string]any{
		"orgs": uiOrgsData{uiBase: sampleBase("orgs", "Organizations"), Orgs: sampleOrgs()},
		"users": uiUsersData{
			uiBase: sampleBase("users", "Users"),
			Users:  []domain.User{sampleUser},
			Orgs:   sampleOrgs(),
		},
		"domains": uiDomainsData{
			uiBase: sampleBase("domains", "Domains"),
			Orgs:   sampleOrgs(), OrgID: "org-1",
			Domains: []domain.Domain{{
				ID: "dom-1", OrganizationID: "org-1", FQDN: "pruxi.in",
				Status: domain.DomainVerified,
			}},
			Hostnames: []domain.Hostname{{
				ID: "host-1", DomainID: "dom-1", Hostname: "mail.pruxi.in", Status: "active",
			}},
		},
		"mail": sampleMailData(),
		"catalog": uiCatalogData{
			uiBase: sampleBase("catalog", "Catalog"),
			Orgs:   sampleOrgs(),
			Apps: []store.CatalogApp{{
				ID: "app-1", Name: "Gitea", Slug: "gitea",
				Version: "1.22", Description: "Git service", Category: "dev",
			}},
		},
		"audit": uiAuditData{
			uiBase: sampleBase("audit", "Audit log"), ActionFilter: "mail.",
			Events: []domain.AuditEvent{{
				ID: "evt-1", OccurredAt: time.Unix(1700000000, 0),
				Action: "mail.identity.created", ResourceType: "mail_identity",
				ResourceID: "mi-1",
			}},
		},
		"setup": uiSetupData{
			uiBase:         sampleBase("", "Setup"),
			Onboarded:      false,
			LocalDomain:    domain.DefaultLocalDomain,
			BootstrapEmail: "admin@selfu.local",
			AdminExists:    true,
			Authenticated:  true,
		},
	}
}

func TestRenderAllPageTemplates(t *testing.T) {
	samples := pageSamples()

	// Every content template present in the parsed set must have a sample.
	for _, tmpl := range uiTemplates.Templates() {
		name := tmpl.Name()
		if name == "head" || name == "nav" || name == "" ||
			strings.HasSuffix(name, ".html") {
			continue
		}
		if _, ok := samples[name]; !ok {
			t.Errorf("page template %q has no render sample — add it to pageSamples()", name)
		}
	}

	for name, data := range samples {
		t.Run(name, func(t *testing.T) {
			if uiTemplates.Lookup(name) == nil {
				t.Fatalf("template %q not defined in web/", name)
			}
			var buf bytes.Buffer
			payload := struct{ Data any }{Data: data}
			if err := template.Must(uiTemplates.Clone()).ExecuteTemplate(&buf, name, payload); err != nil {
				t.Fatalf("ExecuteTemplate(%q): %v", name, err)
			}
			if buf.Len() == 0 {
				t.Fatalf("ExecuteTemplate(%q) rendered empty output", name)
			}
		})
	}
}

func TestRenderMailGroupBoundAlias(t *testing.T) {
	var buf bytes.Buffer
	payload := struct{ Data any }{Data: sampleMailData()}
	if err := template.Must(uiTemplates.Clone()).ExecuteTemplate(&buf, "mail", payload); err != nil {
		t.Fatalf("ExecuteTemplate(mail): %v", err)
	}
	body := buf.String()
	for _, want := range []string{
		"developers@pruxi.in", "support@pruxi.in", "alice@pruxi.in",
		"group: developers", // §42 group-managed badge on the bound alias
	} {
		if !strings.Contains(body, want) {
			t.Errorf("rendered mail page missing %q", want)
		}
	}
}

// TestUIMailResolvesAliasGroups drives the real uiMail handler end to end:
// a group-bound alias must surface its group name, plain aliases must not.
func TestUIMailResolvesAliasGroups(t *testing.T) {
	users := &fakeUsers{byID: map[string]domain.User{"user-1": sampleUser}}
	h, _, sessions, _ := newHandler(t, users)

	ident := newFakeOnboardIdentities()
	ident.groups["group-1"] = domain.Group{ID: "group-1", Name: "developers"}

	gid := "group-1"
	ms := newFakeMailStore()
	ms.mailDomains["dom-1"] = domain.MailDomain{ID: "md-1", DomainID: "dom-1", Status: domain.MailDomainActive}
	ms.aliasesByDomain = map[string][]domain.MailAlias{"dom-1": {
		{ID: "alias-2", OrganizationID: "org-1", DomainID: "dom-1", GroupID: &gid,
			LocalPart: "developers", Address: "developers@pruxi.in", Status: "active"},
	}}

	now := time.Now()
	h.d.IdentityStore = ident
	h.d.DomainStore = &fakeDomainStore{domains: map[string]domain.Domain{
		"dom-1": {ID: "dom-1", OrganizationID: "org-1", FQDN: "pruxi.in"},
	}}
	h.d.MailStore = ms
	h.d.Setup = &fakeSetup{onboardedAt: &now}

	tok, err := sessions.Issue("user-1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "/ui/mail?org=org-1&domain=dom-1", nil)
	r.AddCookie(&http.Cookie{Name: sessions.CookieName(), Value: tok})
	w := httptest.NewRecorder()
	router(t, h).ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("ui/mail status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "group: developers") {
		t.Error("group-bound alias did not show its group name")
	}
	if n := strings.Count(body, "group: "); n != 1 {
		t.Errorf("group badge count = %d, want 1 (plain aliases must not be marked group-managed)", n)
	}
}

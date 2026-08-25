package httpapi

import (
	"embed"
	"html/template"
	"net/http"

	"selfu/internal/domain"
	"selfu/internal/store"
)

//go:embed web/*.html
var uiFS embed.FS

//go:embed web/favicon.svg
var faviconSVG []byte

var uiTemplates = template.Must(template.ParseFS(uiFS, "web/layout.html", "web/*.html"))

// favicon serves the embedded icon; a dedicated route keeps the request
// away from the "/" UI handler (which would redirect it to the IdP).
func (h *Handler) favicon(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write(faviconSVG)
}

// uiBase is the common template data. Title backs the per-page <title>
// ("selfu — <Title>"); when empty the layout falls back to "admin console".
type uiBase struct {
	User   domain.User
	Active string
	Title  string
	Err    string
}

// uiAuditData backs the audit page.
type uiAuditData struct {
	uiBase
	ActionFilter string
	Events       []domain.AuditEvent
}

type uiOrgsData struct {
	uiBase
	Orgs []domain.Organization
}

type uiUsersData struct {
	uiBase
	Users []domain.User
	Orgs  []domain.Organization
}

type uiDomainsData struct {
	uiBase
	Orgs      []domain.Organization
	OrgID     string
	Domains   []domain.Domain
	Hostnames []domain.Hostname
}

type uiMailData struct {
	uiBase
	Orgs       []domain.Organization
	OrgID      string
	DomainID   string
	FQDN       string
	MailDomain *domain.MailDomain
	Identities []domain.MailIdentity
	Aliases    []domain.MailAlias
}

type uiCatalogData struct {
	uiBase
	Orgs []domain.Organization
	Apps []store.CatalogApp
}

// uiSetupData backs the onboarding wizard page.
type uiSetupData struct {
	uiBase
	Onboarded      bool
	LocalDomain    string
	BootstrapEmail string
	AdminExists    bool
	Authenticated  bool
}

// uiRender renders a page template (web/*.html) with a .Data payload so the
// shared head/nav partials and each page access data uniformly as .Data.*.
func (h *Handler) uiRender(w http.ResponseWriter, content string, data any) {
	payload := struct{ Data any }{Data: data}
	if err := uiTemplates.ExecuteTemplate(w, content, payload); err != nil {
		h.d.Logger.Error("ui render failed", "err", err)
	}
}

func (h *Handler) uiDashboard(w http.ResponseWriter, r *http.Request) {
	u, ok := h.uiAuth(w, r)
	if !ok {
		return
	}
	http.Redirect(w, r, "/ui/orgs", http.StatusFound)
	_ = u
}

func (h *Handler) uiOrgs(w http.ResponseWriter, r *http.Request) {
	u, ok := h.uiAuth(w, r)
	if !ok {
		return
	}
	orgs, err := h.d.IdentityStore.ListOrganizations(r.Context(), 500)
	if err != nil {
		h.uiRender(w, "orgs", uiOrgsData{uiBase: uiBase{User: u, Active: "orgs", Title: "Organizations", Err: err.Error()}})
		return
	}
	h.uiRender(w, "orgs", uiOrgsData{uiBase: uiBase{User: u, Active: "orgs", Title: "Organizations"}, Orgs: orgs})
}

func (h *Handler) uiUsers(w http.ResponseWriter, r *http.Request) {
	u, ok := h.uiAuth(w, r)
	if !ok {
		return
	}
	users, _ := h.d.IdentityStore.ListUsers(r.Context(), 500)
	orgs, _ := h.d.IdentityStore.ListOrganizations(r.Context(), 500)
	h.uiRender(w, "users", uiUsersData{uiBase: uiBase{User: u, Active: "users", Title: "Users"}, Users: users, Orgs: orgs})
}

func (h *Handler) uiDomains(w http.ResponseWriter, r *http.Request) {
	u, ok := h.uiAuth(w, r)
	if !ok {
		return
	}
	data := uiDomainsData{uiBase: uiBase{User: u, Active: "domains", Title: "Domains"}}
	orgs, err := h.d.IdentityStore.ListOrganizations(r.Context(), 500)
	if err != nil {
		data.Err = err.Error()
	}
	data.Orgs = orgs
	orgID := r.URL.Query().Get("org")
	if orgID != "" {
		data.OrgID = orgID
		domains, derr := h.d.DomainStore.ListDomainsByOrg(r.Context(), orgID)
		if derr != nil && data.Err == "" {
			data.Err = derr.Error()
		}
		data.Domains = domains
		if d := r.URL.Query().Get("domain"); d != "" {
			dom, err := h.d.DomainStore.GetDomainByID(r.Context(), d)
			if err == nil {
				hostnames, herr := h.d.DomainStore.ListHostnamesByDomain(r.Context(), dom.ID)
				if herr != nil && data.Err == "" {
					data.Err = herr.Error()
				}
				data.Hostnames = hostnames
			}
		}
	}
	h.uiRender(w, "domains", data)
}

func (h *Handler) uiMail(w http.ResponseWriter, r *http.Request) {
	u, ok := h.uiAuth(w, r)
	if !ok {
		return
	}
	data := uiMailData{uiBase: uiBase{User: u, Active: "mail", Title: "Mail"}}
	orgs, err := h.d.IdentityStore.ListOrganizations(r.Context(), 500)
	if err != nil {
		data.Err = err.Error()
	}
	data.Orgs = orgs
	if orgID := r.URL.Query().Get("org"); orgID != "" {
		data.OrgID = orgID
		if domID := r.URL.Query().Get("domain"); domID != "" {
			data.DomainID = domID
			if dom, err := h.d.DomainStore.GetDomainByID(r.Context(), domID); err == nil {
				data.FQDN = dom.FQDN
			}
			if md, err := h.d.MailStore.GetMailDomainByDomainID(r.Context(), domID); err == nil {
				data.MailDomain = &md
			}
			identities, ierr := h.d.MailStore.ListMailIdentitiesByDomain(r.Context(), domID)
			if ierr != nil && data.Err == "" {
				data.Err = ierr.Error()
			}
			data.Identities = identities
			aliases, aerr := h.d.MailStore.ListMailAliasesByDomain(r.Context(), domID)
			if aerr != nil && data.Err == "" {
				data.Err = aerr.Error()
			}
			data.Aliases = aliases
		}
	}
	h.uiRender(w, "mail", data)
}

func (h *Handler) uiCatalog(w http.ResponseWriter, r *http.Request) {
	u, ok := h.uiAuth(w, r)
	if !ok {
		return
	}
	data := uiCatalogData{uiBase: uiBase{User: u, Active: "catalog", Title: "Catalog"}}
	orgs, err := h.d.IdentityStore.ListOrganizations(r.Context(), 500)
	if err != nil {
		data.Err = err.Error()
	}
	data.Orgs = orgs
	apps, aerr := h.d.Apps.ListCatalogApps(r.Context())
	if aerr != nil && data.Err == "" {
		data.Err = aerr.Error()
	}
	data.Apps = apps
	h.uiRender(w, "catalog", data)
}

func (h *Handler) uiAudit(w http.ResponseWriter, r *http.Request) {
	u, ok := h.uiAuth(w, r)
	if !ok {
		return
	}
	action := r.URL.Query().Get("action")
	data := uiAuditData{uiBase: uiBase{User: u, Active: "audit", Title: "Audit log"}, ActionFilter: action}
	events, err := h.d.Audit.ListAuditEvents(r.Context(), 200, action)
	if err != nil {
		data.Err = err.Error()
	} else {
		data.Events = events
	}
	h.uiRender(w, "audit", data)
}

// uiSetup serves the onboarding wizard. It is reachable before login and
// before onboarding: the page adapts to the session/installation state.
func (h *Handler) uiSetup(w http.ResponseWriter, r *http.Request) {
	inst, err := h.d.Setup.GetInstallation(r.Context())
	if err != nil {
		h.uiRender(w, "setup", uiSetupData{uiBase: uiBase{Title: "Setup", Err: err.Error()}})
		return
	}
	data := uiSetupData{
		uiBase:         uiBase{Title: "Setup"},
		Onboarded:      inst.Onboarded(),
		LocalDomain:    inst.LocalDomain,
		BootstrapEmail: h.d.BootstrapEmail,
	}
	if data.Onboarded {
		http.Redirect(w, r, "/ui/orgs", http.StatusFound)
		return
	}
	u, authed := h.authenticate(r)
	data.Authenticated = authed
	if authed {
		data.User = u
		n, _ := h.d.Users.AdminCount(r.Context())
		data.AdminExists = n > 0
	}
	h.uiRender(w, "setup", data)
}

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

var uiTemplates = template.Must(template.ParseFS(uiFS, "web/layout.html", "web/*.html"))

// uiBase is the common template data.
type uiBase struct {
	User   domain.User
	Active string
	Err    string
}

// UI page data.
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

type uiAuditData struct {
	uiBase
	Events []domain.AuditEvent
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
		h.uiRender(w, "orgs", uiOrgsData{uiBase: uiBase{User: u, Active: "orgs", Err: err.Error()}})
		return
	}
	h.uiRender(w, "orgs", uiOrgsData{uiBase: uiBase{User: u, Active: "orgs"}, Orgs: orgs})
}

func (h *Handler) uiUsers(w http.ResponseWriter, r *http.Request) {
	u, ok := h.uiAuth(w, r)
	if !ok {
		return
	}
	users, _ := h.d.IdentityStore.ListUsers(r.Context(), 500)
	orgs, _ := h.d.IdentityStore.ListOrganizations(r.Context(), 500)
	h.uiRender(w, "users", uiUsersData{uiBase: uiBase{User: u, Active: "users"}, Users: users, Orgs: orgs})
}

func (h *Handler) uiDomains(w http.ResponseWriter, r *http.Request) {
	u, ok := h.uiAuth(w, r)
	if !ok {
		return
	}
	orgs, _ := h.d.IdentityStore.ListOrganizations(r.Context(), 500)
	data := uiDomainsData{uiBase: uiBase{User: u, Active: "domains"}, Orgs: orgs}
	orgID := r.URL.Query().Get("org")
	if orgID != "" {
		data.OrgID = orgID
		data.Domains, _ = h.d.DomainStore.ListDomainsByOrg(r.Context(), orgID)
		if d := r.URL.Query().Get("domain"); d != "" {
			dom, err := h.d.DomainStore.GetDomainByID(r.Context(), d)
			if err == nil {
				data.Hostnames, _ = h.d.DomainStore.ListHostnamesByDomain(r.Context(), dom.ID)
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
	orgs, _ := h.d.IdentityStore.ListOrganizations(r.Context(), 500)
	data := uiMailData{uiBase: uiBase{User: u, Active: "mail"}, Orgs: orgs}
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
			data.Identities, _ = h.d.MailStore.ListMailIdentitiesByDomain(r.Context(), domID)
			data.Aliases, _ = h.d.MailStore.ListMailAliasesByDomain(r.Context(), domID)
		}
	}
	h.uiRender(w, "mail", data)
}

func (h *Handler) uiCatalog(w http.ResponseWriter, r *http.Request) {
	u, ok := h.uiAuth(w, r)
	if !ok {
		return
	}
	orgs, _ := h.d.IdentityStore.ListOrganizations(r.Context(), 500)
	apps, _ := h.d.Apps.ListCatalogApps(r.Context())
	h.uiRender(w, "catalog", uiCatalogData{uiBase: uiBase{User: u, Active: "catalog"}, Orgs: orgs, Apps: apps})
}

func (h *Handler) uiAudit(w http.ResponseWriter, r *http.Request) {
	u, ok := h.uiAuth(w, r)
	if !ok {
		return
	}
	events, _ := h.d.Audit.ListAuditEvents(r.Context(), 200)
	h.uiRender(w, "audit", uiAuditData{uiBase: uiBase{User: u, Active: "audit"}, Events: events})
}

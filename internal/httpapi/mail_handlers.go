package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"selfu/internal/domain"
	"selfu/internal/provision"
	"selfu/internal/recon"
	"selfu/internal/store"
)

// MailStore is the mail persistence surface. *store.Store satisfies it.
// enableMail implements spec §27: a verified domain becomes a mail domain.
func (h *Handler) enableMail(w http.ResponseWriter, r *http.Request) {
	d, err := h.d.DomainStore.GetDomainByID(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "domain not found")
		return
	}
	if !h.requireOrgRole(w, r, d.OrganizationID, domain.RoleAdmin) {
		return
	}
	if d.Status != domain.DomainVerified {
		writeError(w, http.StatusConflict, "domain_not_verified", "only verified domains can enable mail")
		return
	}
	if h.d.Chasquid == nil {
		writeError(w, http.StatusUnprocessableEntity, "mail_unavailable", "mail provisioning is not configured")
		return
	}
	if _, err := h.d.MailStore.GetMailDomainByDomainID(r.Context(), d.ID); err == nil {
		writeError(w, http.StatusConflict, "conflict", "mail already enabled for this domain")
		return
	}
	md, err := h.d.MailStore.CreateMailDomain(r.Context(), d.ID)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "conflict", "mail already enabled for this domain")
			return
		}
		h.internalError(w, err)
		return
	}
	// Provision the chasquid domain (spec §29).
	if err := h.d.Chasquid.EnsureDomain(r.Context(), d.FQDN); err != nil {
		h.d.Logger.Warn("chasquid ensure domain failed", "err", err, "domain", d.FQDN)
		_ = h.d.MailStore.SetMailDomainStatus(r.Context(), md.ID, "disabled")
		writeError(w, http.StatusUnprocessableEntity, "provisioning_failed", "could not provision the mail domain")
		return
	}
	// New domains require a restart to be registered by chasquid (spec §91).
	_ = h.d.Chasquid.Restart(r.Context())
	// Provision DKIM (spec §28, §68): keygen + record for DNS publication.
	if dk, err := h.d.Chasquid.EnsureDKIM(r.Context(), d.FQDN); err == nil {
		if err := h.d.MailStore.SetMailDomainDKIM(r.Context(), md.ID, dk.Selector, dk.Record); err != nil {
			h.d.Logger.Warn("store dkim metadata failed", "err", err)
		}
	} else {
		h.d.Logger.Warn("dkim provisioning failed", "err", err, "domain", d.FQDN)
	}
	_ = h.d.MailStore.SetMailDomainStatus(r.Context(), md.ID, "active")

	h.audit(r.Context(), domain.AuditEvent{
		ActorUserID:  new(rUser(r).ID),
		Action:       "mail.domain.enabled",
		ResourceType: "domain",
		ResourceID:   d.ID,
		Details:      map[string]any{"fqdn": d.FQDN},
	})
	writeJSON(w, http.StatusCreated, map[string]any{"mail_domain": md})
}

func (h *Handler) mailStatus(w http.ResponseWriter, r *http.Request) {
	d, err := h.d.DomainStore.GetDomainByID(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "domain not found")
		return
	}
	if !h.requireOrgRole(w, r, d.OrganizationID, domain.RoleMember) {
		return
	}
	md, err := h.d.MailStore.GetMailDomainByDomainID(r.Context(), d.ID)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "mail not enabled for this domain")
		return
	}
	resp := map[string]any{"mail_domain": md}
	if h.d.Chasquid != nil {
		if st, err := h.d.Chasquid.Status(r.Context()); err == nil {
			resp["chasquid_health"] = st
		}
		if state, err := h.d.Chasquid.CheckDomain(r.Context(), d.FQDN); err == nil {
			resp["chasquid_domain"] = state
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// reconcileMail runs one conservative pass using the shared reconciler
// (spec §92; same logic as the background worker, spec §21).
func (h *Handler) reconcileMail(w http.ResponseWriter, r *http.Request) {
	d, err := h.d.DomainStore.GetDomainByID(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "domain not found")
		return
	}
	if !h.requireOrgRole(w, r, d.OrganizationID, domain.RoleAdmin) {
		return
	}
	if _, err := h.d.MailStore.GetMailDomainByDomainID(r.Context(), d.ID); err != nil {
		writeError(w, http.StatusNotFound, "not_found", "mail not enabled for this domain")
		return
	}
	if h.d.Chasquid == nil {
		writeError(w, http.StatusUnprocessableEntity, "mail_unavailable", "mail provisioning is not configured")
		return
	}

	rec := &recon.MailReconciler{
		Store:        h.d.Recon,
		Chasquid:     h.d.Chasquid,
		Audit:        h.d.Audit,
		Logger:       h.d.Logger,
		ProviderName: h.d.ProviderName,
	}
	res, err := rec.ReconcileDomain(r.Context(), d.ID, d.FQDN, d.OrganizationID)
	if err != nil {
		h.internalError(w, err)
		return
	}

	h.audit(r.Context(), domain.AuditEvent{
		ActorUserID:  new(rUser(r).ID),
		Action:       "mail.reconciliation",
		ResourceType: "domain",
		ResourceID:   d.ID,
		Details: map[string]any{
			"aliases_restored":   res.AliasesRestored + res.GroupAliases,
			"identities_missing": len(res.MissingUsers),
		},
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"domain_id":          d.ID,
		"aliases_restored":   res.AliasesRestored + res.GroupAliases,
		"identities_missing": emptyOr(res.MissingUsers),
		"note":               "missing identities are suspended, never recreated (spec §92)",
	})
}

func emptyOr(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (h *Handler) disableMail(w http.ResponseWriter, r *http.Request) {
	d, err := h.d.DomainStore.GetDomainByID(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "domain not found")
		return
	}
	if !h.requireOrgRole(w, r, d.OrganizationID, domain.RoleAdmin) {
		return
	}
	md, err := h.d.MailStore.GetMailDomainByDomainID(r.Context(), d.ID)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "mail not enabled for this domain")
		return
	}
	// Disable, do not destroy (spec §63: retain mailbox/data by default).
	if err := h.d.MailStore.SetMailDomainStatus(r.Context(), md.ID, "disabled"); err != nil {
		h.internalError(w, err)
		return
	}
	h.audit(r.Context(), domain.AuditEvent{
		ActorUserID:  new(rUser(r).ID),
		Action:       "mail.domain.disabled",
		ResourceType: "domain",
		ResourceID:   d.ID,
	})
	writeJSON(w, http.StatusOK, map[string]any{"status": "disabled"})
}

type createMailIdentityReq struct {
	LocalPart string `json:"local_part"`
	UserID    string `json:"user_id"`
}

// createMailIdentity provisions a mailbox identity (spec §30–§34): platform
// user + chasquid user + independent SMTP credential (spec §35).
func (h *Handler) createMailIdentity(w http.ResponseWriter, r *http.Request) {
	d, err := h.d.DomainStore.GetDomainByID(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "domain not found")
		return
	}
	if !h.requireOrgRole(w, r, d.OrganizationID, domain.RoleAdmin) {
		return
	}
	md, err := h.d.MailStore.GetMailDomainByDomainID(r.Context(), d.ID)
	if err != nil || md.Status != "active" {
		writeError(w, http.StatusConflict, "mail_not_active", "mail must be enabled and active for this domain")
		return
	}
	var req createMailIdentityReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if h.d.Chasquid == nil {
		writeError(w, http.StatusUnprocessableEntity, "mail_unavailable", "mail provisioning is not configured")
		return
	}
	addr, err := domain.BuildAddress(req.LocalPart, d.FQDN)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if req.UserID != "" {
		if _, err := h.d.IdentityStore.GetMembershipRole(r.Context(), d.OrganizationID, req.UserID); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "user is not a member of this organization")
			return
		}
	}

	ident, credID, secret, err := provision.Provisioner(r.Context(), h.d.MailStore, h.d.MailProvision, domain.MailIdentity{
		OrganizationID:   d.OrganizationID,
		UserID:           optionalStringPtr(req.UserID),
		DomainID:         d.ID,
		Address:          addr,
		ChasquidUsername: addr,
	})
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "conflict", "address already in use")
			return
		}
		writeError(w, http.StatusUnprocessableEntity, "provisioning_failed", "could not provision the mailbox")
		return
	}
	cred := domain.MailCredential{ID: credID}

	h.audit(r.Context(), domain.AuditEvent{
		ActorUserID:  new(rUser(r).ID),
		Action:       "mail.identity.created",
		ResourceType: "mail_identity",
		ResourceID:   ident.ID,
		Details:      map[string]any{"address": addr},
	})
	writeJSON(w, http.StatusCreated, map[string]any{
		"identity":   ident,
		"credential": map[string]any{"id": cred.ID, "secret": string(secret), "note": "shown once; store it now"},
	})
}

// rotateMailCredential issues a fresh SMTP secret (spec §36).
func (h *Handler) rotateMailCredential(w http.ResponseWriter, r *http.Request) {
	ident, err := h.d.MailStore.GetMailIdentity(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "mail identity not found")
		return
	}
	if !h.requireOrgRole(w, r, ident.OrganizationID, domain.RoleAdmin) {
		return
	}
	if h.d.Chasquid == nil {
		writeError(w, http.StatusUnprocessableEntity, "mail_unavailable", "mail provisioning is not configured")
		return
	}
	credID, secret, err := provision.Rotate(r.Context(), h.d.MailStore, h.d.MailProvision, ident)
	if err != nil {
		h.d.Logger.Warn("credential rotation failed", "err", err, "address", ident.ChasquidUsername)
		writeError(w, http.StatusUnprocessableEntity, "rotation_failed", "could not rotate the credential")
		return
	}
	cred := domain.MailCredential{ID: credID}
	h.audit(r.Context(), domain.AuditEvent{
		ActorUserID:  new(rUser(r).ID),
		Action:       "mail.identity.credential_rotated",
		ResourceType: "mail_identity",
		ResourceID:   ident.ID,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"credential": map[string]any{"id": cred.ID, "secret": string(secret), "note": "shown once; store it now"},
	})
}

func (h *Handler) listMailIdentities(w http.ResponseWriter, r *http.Request) {
	d, err := h.d.DomainStore.GetDomainByID(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "domain not found")
		return
	}
	if !h.requireOrgRole(w, r, d.OrganizationID, domain.RoleMember) {
		return
	}
	list, err := h.d.MailStore.ListMailIdentitiesByDomain(r.Context(), d.ID)
	if err != nil {
		h.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

type createMailAliasReq struct {
	LocalPart    string   `json:"local_part"`
	Destinations []string `json:"destinations"`
	GroupID      *string  `json:"group_id"`
}

// createMailAlias enforces same-organization routing by default (spec §39)
// and supports group-bound aliases (§42–43).
func (h *Handler) createMailAlias(w http.ResponseWriter, r *http.Request) {
	d, err := h.d.DomainStore.GetDomainByID(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "domain not found")
		return
	}
	if !h.requireOrgRole(w, r, d.OrganizationID, domain.RoleAdmin) {
		return
	}
	var req createMailAliasReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	// Group-bound aliases derive destinations from the members' active
	// identities (spec §42); the set is recomputed on reconciliation.
	if req.GroupID != nil {
		g, err := h.d.IdentityStore.GetGroupByID(r.Context(), *req.GroupID)
		if err != nil || g.OrganizationID != d.OrganizationID {
			writeError(w, http.StatusBadRequest, "invalid_group", "group does not belong to this organization")
			return
		}
		members, err := h.d.IdentityStore.ListGroupMembers(r.Context(), *req.GroupID)
		if err != nil {
			h.internalError(w, err)
			return
		}
		userIDs := make([]string, 0, len(members))
		for _, m := range members {
			userIDs = append(userIDs, m.UserID)
		}
		identities, err := h.d.MailStore.ListMailIdentitiesByUsers(r.Context(), d.OrganizationID, userIDs)
		if err != nil {
			h.internalError(w, err)
			return
		}
		req.Destinations = nil
		for _, idn := range identities {
			req.Destinations = append(req.Destinations, idn.Address)
		}
	}
	if len(req.Destinations) == 0 && req.GroupID == nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "at least one destination is required")
		return
	}
	addr, err := domain.BuildAddress(req.LocalPart, d.FQDN)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	// Destinations must be mail identities of THIS organization.
	for _, dest := range req.Destinations {
		idn, err := h.d.MailStore.GetMailIdentityByAddress(r.Context(), dest)
		if err != nil || idn.OrganizationID != d.OrganizationID {
			writeError(w, http.StatusBadRequest, "invalid_destination",
				"destination "+dest+" is not a mail identity of this organization (cross-organization routing is disabled)")
			return
		}
	}
	if h.d.Chasquid == nil {
		writeError(w, http.StatusUnprocessableEntity, "mail_unavailable", "mail provisioning is not configured")
		return
	}
	if err := h.d.Chasquid.EnsureAlias(r.Context(), d.FQDN, strings.Split(addr, "@")[0], req.Destinations); err != nil {
		h.d.Logger.Warn("chasquid alias failed", "err", err)
		writeError(w, http.StatusUnprocessableEntity, "provisioning_failed", "could not provision the alias")
		return
	}
	alias, err := h.d.MailStore.CreateMailAlias(r.Context(), domain.MailAlias{
		OrganizationID: d.OrganizationID,
		DomainID:       d.ID,
		GroupID:        req.GroupID,
		LocalPart:      strings.Split(addr, "@")[0],
		Address:        addr,
		Destinations:   req.Destinations,
	})
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "conflict", "alias already exists")
			return
		}
		h.internalError(w, err)
		return
	}
	h.audit(r.Context(), domain.AuditEvent{
		ActorUserID:  new(rUser(r).ID),
		Action:       "mail.alias.created",
		ResourceType: "mail_alias",
		ResourceID:   alias.ID,
		Details:      map[string]any{"address": addr, "destinations": req.Destinations},
	})
	writeJSON(w, http.StatusCreated, alias)
}

func (h *Handler) listMailAliases(w http.ResponseWriter, r *http.Request) {
	d, err := h.d.DomainStore.GetDomainByID(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "domain not found")
		return
	}
	if !h.requireOrgRole(w, r, d.OrganizationID, domain.RoleMember) {
		return
	}
	list, err := h.d.MailStore.ListMailAliasesByDomain(r.Context(), d.ID)
	if err != nil {
		h.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func optionalStringPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

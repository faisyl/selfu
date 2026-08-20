package httpapi

import (
	"errors"
	"net/http"
	"time"

	"selfu/internal/dns"
	"selfu/internal/domain"
	"selfu/internal/store"
)

// DomainStore is the domain/hostname persistence surface. *store.Store
// satisfies it.
type createDomainReq struct {
	FQDN string `json:"fqdn"`
}

func (h *Handler) createDomain(w http.ResponseWriter, r *http.Request) {
	orgID := r.PathValue("id")
	if !h.requireOrgRole(w, r, orgID, domain.RoleAdmin) {
		return
	}
	var req createDomainReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	d, err := domain.NewDomain(orgID, req.FQDN)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	created, err := h.d.DomainStore.CreateDomain(r.Context(), d)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "conflict", "domain already registered for this organization")
			return
		}
		h.internalError(w, err)
		return
	}

	// Produce ownership instructions (Manual provider emits them; an
	// automated provider may try to set the record).
	recordName := dns.VerifyRecordName(created.FQDN)
	recordValue := dns.TokenTXTValue(created.VerificationToken)
	automated := false
	if h.d.DNSProvider != nil {
		if perr := h.d.DNSProvider.SetTXT(r.Context(), recordName, recordValue); perr == nil {
			automated = true
		}
	}

	h.audit(r.Context(), domain.AuditEvent{
		ActorUserID:  new(rUser(r).ID),
		Action:       "domain.created",
		ResourceType: "domain",
		ResourceID:   created.ID,
		Details:      map[string]any{"fqdn": created.FQDN},
	})

	writeJSON(w, http.StatusCreated, map[string]any{
		"domain": created,
		"verification": map[string]any{
			"record_name":  recordName,
			"record_value": recordValue,
			"automated":    automated,
		},
	})
}

func (h *Handler) listDomains(w http.ResponseWriter, r *http.Request) {
	orgID := r.PathValue("id")
	if !h.requireOrgRole(w, r, orgID, domain.RoleMember) {
		return
	}
	list, err := h.d.DomainStore.ListDomainsByOrg(r.Context(), orgID)
	if err != nil {
		h.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (h *Handler) verifyDomain(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	d, err := h.d.DomainStore.GetDomainByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "domain not found")
		return
	}
	if !h.requireOrgRole(w, r, d.OrganizationID, domain.RoleAdmin) {
		return
	}

	recordName := dns.VerifyRecordName(d.FQDN)
	recordValue := dns.TokenTXTValue(d.VerificationToken)

	if h.d.TXTLookup == nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "DNS lookup unavailable")
		return
	}
	txts, err := h.d.TXTLookup(r.Context(), recordName)
	if err != nil {
		_ = h.d.DomainStore.LogVerification(r.Context(), d.ID, d.VerificationMethod, err.Error(), false)
		h.d.Logger.Warn("domain verification lookup failed", "err", err, "domain", d.FQDN)
		writeError(w, http.StatusUnprocessableEntity, "lookup_failed", "could not query DNS for the verification record")
		return
	}

	verified := false
	for _, t := range txts {
		if t == recordValue {
			verified = true
			break
		}
	}
	if verified {
		now := time.Now().UTC()
		if err := h.d.DomainStore.SetDomainStatus(r.Context(), d.ID, domain.DomainVerified, &now); err != nil {
			h.internalError(w, err)
			return
		}
		_ = h.d.DomainStore.LogVerification(r.Context(), d.ID, d.VerificationMethod, "verified", true)
		h.audit(r.Context(), domain.AuditEvent{
			ActorUserID:  new(rUser(r).ID),
			Action:       "domain.verified",
			ResourceType: "domain",
			ResourceID:   d.ID,
			Details:      map[string]any{"fqdn": d.FQDN},
		})
		writeJSON(w, http.StatusOK, map[string]any{"status": string(domain.DomainVerified)})
		return
	}

	_ = h.d.DomainStore.LogVerification(r.Context(), d.ID, d.VerificationMethod, "record not found", false)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":   string(d.Status),
		"verified": false,
		"hint":     "set TXT " + recordName + " to " + recordValue,
	})
}

func (h *Handler) deleteDomain(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	d, err := h.d.DomainStore.GetDomainByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "domain not found")
		return
	}
	if !h.requireOrgRole(w, r, d.OrganizationID, domain.RoleAdmin) {
		return
	}
	if err := h.d.DomainStore.DeleteDomain(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrHasDependents) {
			writeError(w, http.StatusConflict, "dependents", "domain has application hostnames; remove them first")
			return
		}
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "domain not found")
			return
		}
		h.internalError(w, err)
		return
	}
	h.audit(r.Context(), domain.AuditEvent{
		ActorUserID:  new(rUser(r).ID),
		Action:       "domain.deleted",
		ResourceType: "domain",
		ResourceID:   id,
	})
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

type addHostnameReq struct {
	Hostname string `json:"hostname"`
}

func (h *Handler) addHostname(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	d, err := h.d.DomainStore.GetDomainByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "domain not found")
		return
	}
	if !h.requireOrgRole(w, r, d.OrganizationID, domain.RoleAdmin) {
		return
	}
	var req addHostnameReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if req.Hostname == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "hostname is required")
		return
	}
	// Only verified domains may back public hostnames (spec §10, §12).
	if d.Status != domain.DomainVerified {
		writeError(w, http.StatusConflict, "domain_not_verified", "domain must be verified before binding hostnames")
		return
	}
	if !domain.HostnameWithinDomain(req.Hostname, d.FQDN) {
		writeError(w, http.StatusBadRequest, "not_within_domain", "hostname is not contained within the verified domain")
		return
	}
	norm, err := domain.NormalizeDomain(req.Hostname)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	created, err := h.d.DomainStore.AddHostname(r.Context(), domain.Hostname{
		DomainID: d.ID,
		Hostname: norm,
	})
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "conflict", "hostname already bound to this domain")
			return
		}
		h.internalError(w, err)
		return
	}
	h.audit(r.Context(), domain.AuditEvent{
		ActorUserID:  new(rUser(r).ID),
		Action:       "hostname.created",
		ResourceType: "hostname",
		ResourceID:   created.ID,
		Details:      map[string]any{"hostname": norm},
	})
	writeJSON(w, http.StatusCreated, created)
}

func (h *Handler) listHostnames(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	d, err := h.d.DomainStore.GetDomainByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "domain not found")
		return
	}
	if !h.requireOrgRole(w, r, d.OrganizationID, domain.RoleMember) {
		return
	}
	list, err := h.d.DomainStore.ListHostnamesByDomain(r.Context(), id)
	if err != nil {
		h.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

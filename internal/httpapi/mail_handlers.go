package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"

	"selfu/internal/chasquid"
	"selfu/internal/domain"
	"selfu/internal/store"
)

// MailStore is the mail persistence surface. *store.Store satisfies it.
type MailStore interface {
	CreateMailDomain(ctx context.Context, domainID string) (domain.MailDomain, error)
	GetMailDomainByDomainID(ctx context.Context, domainID string) (domain.MailDomain, error)
	SetMailDomainStatus(ctx context.Context, id, status string) error
	SetMailDomainDKIM(ctx context.Context, id, selector, record string) error

	CreateMailIdentity(ctx context.Context, m domain.MailIdentity) (domain.MailIdentity, error)
	GetMailIdentity(ctx context.Context, id string) (domain.MailIdentity, error)
	GetMailIdentityByAddress(ctx context.Context, address string) (domain.MailIdentity, error)
	ListMailIdentitiesByDomain(ctx context.Context, domainID string) ([]domain.MailIdentity, error)
	SetMailIdentityStatus(ctx context.Context, id, status string) error

	CreateMailCredential(ctx context.Context, c domain.MailCredential) (domain.MailCredential, error)
	RevokeCredentialsByIdentity(ctx context.Context, identityID string) error

	CreateMailAlias(ctx context.Context, a domain.MailAlias) (domain.MailAlias, error)
	GetMailAliasByAddress(ctx context.Context, address string) (domain.MailAlias, error)
	ListMailAliasesByDomain(ctx context.Context, domainID string) ([]domain.MailAlias, error)
	DeleteMailAlias(ctx context.Context, id string) error

	CreateMailSubmissionPolicy(ctx context.Context, p domain.MailSubmissionPolicy) error
}

// newSMTPSecret generates an independent, high-entropy SMTP credential
// (spec §35: never reuse authentik passwords).
func newSMTPSecret() (chasquid.Secret, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	s := base64.RawURLEncoding.EncodeToString(b)
	if len(s) < 24 {
		return "", errors.New("generated secret too short")
	}
	return chasquid.Secret(s), nil
}

func fingerprint(s chasquid.Secret) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

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

// reconcileMail conservatively re-aligns desired vs observed chasquid state
// (spec §92): aliases are restored; missing users are flagged (never
// re-created — credentials are stored as fingerprints only).
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

	aliasesRestored := 0
	aliases, err := h.d.MailStore.ListMailAliasesByDomain(r.Context(), d.ID)
	if err != nil {
		h.internalError(w, err)
		return
	}
	for _, a := range aliases {
		if a.Status != "active" {
			continue
		}
		if err := h.d.Chasquid.EnsureAlias(r.Context(), d.FQDN, a.LocalPart, a.Destinations); err != nil {
			h.d.Logger.Warn("alias reconcile failed", "err", err, "address", a.Address)
			continue
		}
		aliasesRestored++
	}
	_ = h.d.Chasquid.Reload(r.Context())

	missingUsers := []string{}
	identities, err := h.d.MailStore.ListMailIdentitiesByDomain(r.Context(), d.ID)
	if err != nil {
		h.internalError(w, err)
		return
	}
	for _, idn := range identities {
		if idn.Status != domain.MailIdentityActive {
			continue
		}
		ok, err := h.d.Chasquid.UserExists(r.Context(), idn.Address)
		if err != nil {
			continue
		}
		if !ok {
			missingUsers = append(missingUsers, idn.Address)
			_ = h.d.MailStore.SetMailIdentityStatus(r.Context(), idn.ID, domain.MailIdentitySuspended)
			h.audit(r.Context(), domain.AuditEvent{
				ActorUserID:  new(rUser(r).ID),
				Action:       "mail.identity.reconciliation_failed",
				ResourceType: "mail_identity",
				ResourceID:   idn.ID,
				Details:      map[string]any{"address": idn.Address, "reason": "chasquid user missing"},
			})
		}
	}

	h.audit(r.Context(), domain.AuditEvent{
		ActorUserID:  new(rUser(r).ID),
		Action:       "mail.reconciliation",
		ResourceType: "domain",
		ResourceID:   d.ID,
		Details:      map[string]any{"aliases_restored": aliasesRestored, "identities_missing": len(missingUsers)},
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"domain_id":          d.ID,
		"aliases_restored":   aliasesRestored,
		"identities_missing": missingUsers,
		"note":               "missing identities are suspended, never recreated (spec §92)",
	})
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

	secret, err := newSMTPSecret()
	if err != nil {
		h.internalError(w, err)
		return
	}
	ident, err := h.d.MailStore.CreateMailIdentity(r.Context(), domain.MailIdentity{
		OrganizationID:   d.OrganizationID,
		UserID:           optionalStringPtr(req.UserID),
		DomainID:         d.ID,
		LocalPart:        strings.Split(addr, "@")[0],
		Address:          addr,
		ChasquidUsername: addr,
		Status:           domain.MailIdentityProvisioning,
	})
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "conflict", "address already in use")
			return
		}
		h.internalError(w, err)
		return
	}
	cred, err := h.d.MailStore.CreateMailCredential(r.Context(), domain.MailCredential{
		MailIdentityID:    ident.ID,
		SecretFingerprint: fingerprint(secret),
	})
	if err != nil {
		h.internalError(w, err)
		return
	}
	if err := h.d.Chasquid.AddUser(r.Context(), addr, secret); err != nil {
		h.d.Logger.Warn("chasquid add user failed", "err", err, "address", addr)
		_ = h.d.MailStore.SetMailIdentityStatus(r.Context(), ident.ID, domain.MailIdentityDeleted)
		writeError(w, http.StatusUnprocessableEntity, "provisioning_failed", "could not provision the mailbox")
		return
	}
	// Sender policy: this credential may only send as its own address
	// (spec §46, §50) — enforced by the post-data hook (G4b).
	_ = h.d.MailStore.CreateMailSubmissionPolicy(r.Context(), domain.MailSubmissionPolicy{
		MailIdentityID:       ident.ID,
		CredentialID:         cred.ID,
		AllowedFromAddresses: []string{addr},
	})
	if err := h.d.Chasquid.EnsureSenderPolicy(r.Context(), addr, []string{addr}); err != nil {
		h.d.Logger.Warn("sender policy install failed", "err", err, "address", addr)
	}
	_ = h.d.MailStore.SetMailIdentityStatus(r.Context(), ident.ID, domain.MailIdentityActive)

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
	secret, err := newSMTPSecret()
	if err != nil {
		h.internalError(w, err)
		return
	}
	if err := h.d.Chasquid.ChangePassword(r.Context(), ident.ChasquidUsername, secret); err != nil {
		h.d.Logger.Warn("chasquid change password failed", "err", err, "address", ident.ChasquidUsername)
		writeError(w, http.StatusUnprocessableEntity, "rotation_failed", "could not rotate the credential")
		return
	}
	if err := h.d.MailStore.RevokeCredentialsByIdentity(r.Context(), ident.ID); err != nil {
		h.internalError(w, err)
		return
	}
	cred, err := h.d.MailStore.CreateMailCredential(r.Context(), domain.MailCredential{
		MailIdentityID:    ident.ID,
		SecretFingerprint: fingerprint(secret),
	})
	if err != nil {
		h.internalError(w, err)
		return
	}
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
}

// createMailAlias enforces same-organization routing by default (spec §39).
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
	if len(req.Destinations) == 0 {
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

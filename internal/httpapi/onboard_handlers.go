package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"selfu/internal/domain"
	"selfu/internal/provision"
	"selfu/internal/store"
)

// onboardUserReq is the composite onboarding payload (spec §79 + §30–35 in
// one call): user, membership, optional group and mailbox.
type onboardUserReq struct {
	Email            string         `json:"email"`
	DisplayName      string         `json:"display_name"`
	Role             domain.OrgRole `json:"role"`
	GroupID          string         `json:"group_id"`
	ProvisionMailbox bool           `json:"provision_mailbox"`
	LocalPart        string         `json:"local_part"`
}

// onboardCredentialResp carries the one-time SMTP secret.
type onboardCredentialResp struct {
	ID     string `json:"id"`
	Secret string `json:"secret,omitempty"`
	Note   string `json:"note,omitempty"`
}

type onboardUserResp struct {
	User         domain.User                   `json:"user"`
	Membership   domain.OrganizationMembership `json:"membership"`
	Group        *domain.Group                 `json:"group,omitempty"`
	MailIdentity *domain.MailIdentity          `json:"mail_identity,omitempty"`
	Credential   *onboardCredentialResp        `json:"credential,omitempty"`
}

// onboardUser composes the add-user workflow into a single idempotent call:
// platform user (upsert by email) + org membership + optional group + optional
// mailbox identity. Re-running with the same email returns the existing user,
// membership, group and mail identity rows without duplicating any of them.
func (h *Handler) onboardUser(w http.ResponseWriter, r *http.Request) {
	orgID := r.PathValue("id")
	actor := rUser(r)
	if !h.requireOrgRole(w, r, orgID, domain.RoleAdmin) {
		return
	}
	var req onboardUserReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	if req.Email == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "email is required")
		return
	}
	role := req.Role
	if role == "" {
		role = domain.RoleMember
	}
	if !role.Valid() {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid role")
		return
	}
	// Only an owner may onboard someone with the owner role. Platform admins
	// are superusers (same bypass requireOrgRole applies).
	if role == domain.RoleOwner && !actor.IsAdmin {
		actorRole, err := h.d.IdentityStore.GetMembershipRole(r.Context(), orgID, actor.ID)
		if err != nil || !actorRole.CanManage(domain.RoleOwner) {
			writeError(w, http.StatusForbidden, "forbidden", "only an owner can onboard with the owner role")
			return
		}
	}

	// Resolve the mailbox target before creating anything so a missing mail
	// domain fails cleanly instead of leaving a half-onboarded user.
	var (
		mailDomain    *domain.Domain
		addr          string
		existingIdent *domain.MailIdentity
	)
	if req.ProvisionMailbox {
		md, _ := h.activeOrgMailDomain(r.Context(), orgID)
		if md == nil {
			writeError(w, http.StatusUnprocessableEntity, "no_mail_domain",
				"organization has no verified domain with active mail; enable mail on a verified domain first")
			return
		}
		// Only the MTA seam is required here: provision.Provisioner talks to
		// MailProvision directly and never touches the chasquid controller.
		if h.d.MailProvision == nil {
			writeError(w, http.StatusUnprocessableEntity, "mail_unavailable", "mail provisioning is not configured")
			return
		}
		localPart := req.LocalPart
		if localPart == "" {
			localPart = strings.SplitN(req.Email, "@", 2)[0]
		}
		a, err := domain.BuildAddress(localPart, md.FQDN)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		addr = a
		mailDomain = md
		if ident, err := h.d.MailStore.GetMailIdentityByAddress(r.Context(), addr); err == nil {
			existingIdent = &ident
		}
	}

	// User: upsert by email — an existing row is reused untouched.
	user, uerr := h.d.IdentityStore.GetUserByEmail(r.Context(), req.Email)
	newUser := false
	if errors.Is(uerr, store.ErrNotFound) {
		pk := ""
		if h.d.Identity != nil {
			p, _, perr := h.d.Identity.EnsureUser(r.Context(), req.Email, req.DisplayName)
			if perr != nil {
				// Best-effort: external identity provisioning must not abort
				// onboarding; reconciliation repairs it later.
				h.d.Logger.Warn("authentik user provisioning failed", "err", perr)
			} else {
				pk = p
			}
		}
		user, uerr = h.d.IdentityStore.CreateUser(r.Context(), req.Email, req.DisplayName, h.d.ProviderName, pk)
		if uerr != nil {
			if errors.Is(uerr, store.ErrConflict) {
				writeError(w, http.StatusConflict, "conflict", "user already exists")
				return
			}
			h.internalError(w, uerr)
			return
		}
		newUser = true
		if pk != "" {
			if _, err := h.d.IdentityStore.UpsertExternalResource(r.Context(), domain.ExternalResource{
				ResourceType:     domain.ResTypeAuthentikUser,
				PlatformObjectID: user.ID,
				Provider:         h.d.ProviderName,
				ExternalID:       pk,
				Status:           domain.ExtActive,
			}); err != nil {
				h.d.Logger.Warn("external mapping failed", "err", err)
			}
		}
	} else if uerr != nil {
		h.internalError(w, uerr)
		return
	}

	membership, err := h.d.IdentityStore.SetMembership(r.Context(), orgID, user.ID, role)
	if err != nil {
		h.internalError(w, err)
		return
	}

	var grp *domain.Group
	if req.GroupID != "" {
		g, gerr := h.d.IdentityStore.GetGroupByID(r.Context(), req.GroupID)
		if gerr != nil || g.OrganizationID != orgID {
			writeError(w, http.StatusBadRequest, "invalid_group", "group does not belong to this organization")
			return
		}
		if err := h.d.IdentityStore.AddGroupMember(r.Context(), g.ID, user.ID); err != nil {
			h.internalError(w, err)
			return
		}
		grp = &g
	}

	var (
		ident *domain.MailIdentity
		cred  *onboardCredentialResp
	)
	if req.ProvisionMailbox {
		if existingIdent != nil {
			// Idempotent re-run: the identity already exists, so no fresh SMTP
			// secret is minted — credentials are shown exactly once, at
			// creation time (same semantics as the mail-identity flow).
			ident = existingIdent
		} else {
			idn, credID, secret, perr := provision.Provisioner(r.Context(), h.d.MailStore, h.d.MailProvision, domain.MailIdentity{
				OrganizationID:   orgID,
				UserID:           &user.ID,
				DomainID:         mailDomain.ID,
				LocalPart:        localPartOf(addr),
				Address:          addr,
				ChasquidUsername: addr,
			})
			if perr != nil {
				if errors.Is(perr, store.ErrConflict) {
					writeError(w, http.StatusConflict, "conflict", "address already in use")
					return
				}
				// The user and membership above already landed: surface the
				// partial state rather than pretending the whole call failed.
				writeError(w, http.StatusUnprocessableEntity, "provisioning_failed",
					"mailbox provisioning failed; the user and membership were created")
				return
			}
			ident = &idn
			cred = &onboardCredentialResp{ID: credID, Secret: string(secret), Note: "shown once; store it now"}
		}
	}

	actorID := actor.ID
	h.audit(r.Context(), domain.AuditEvent{
		ActorUserID:  &actorID,
		Action:       "user.onboarded",
		ResourceType: "organization",
		ResourceID:   orgID,
		Details: map[string]any{
			"email":               user.Email,
			"user_id":             user.ID,
			"role":                string(role),
			"user_created":        newUser,
			"group_id":            req.GroupID,
			"mailbox_provisioned": req.ProvisionMailbox,
		},
	})
	writeJSON(w, http.StatusOK, onboardUserResp{
		User:         user,
		Membership:   membership,
		Group:        grp,
		MailIdentity: ident,
		Credential:   cred,
	})
}

// activeOrgMailDomain picks the organization's first verified domain that has
// an active mail domain — the default mailbox target.
func (h *Handler) activeOrgMailDomain(ctx context.Context, orgID string) (*domain.Domain, *domain.MailDomain) {
	domains, err := h.d.DomainStore.ListDomainsByOrg(ctx, orgID)
	if err != nil {
		return nil, nil
	}
	for _, d := range domains {
		if d.Status != domain.DomainVerified {
			continue
		}
		md, merr := h.d.MailStore.GetMailDomainByDomainID(ctx, d.ID)
		if merr != nil || md.Status != domain.MailDomainActive {
			continue
		}
		dd, mm := d, md
		return &dd, &mm
	}
	return nil, nil
}

func localPartOf(addr string) string {
	return strings.SplitN(addr, "@", 2)[0]
}

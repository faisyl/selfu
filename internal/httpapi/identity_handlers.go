package httpapi

import (
	"context"
	"errors"
	"net/http"

	"selfu/internal/authentik"
	"selfu/internal/domain"
	"selfu/internal/store"
)

// IdentityProvisioner provisions external identity resources in authentik
// (spec §16, §79): users/groups for accounts, plus per-app OIDC and
// forward-auth providers (spec §82, §83). One interface replaces the
// previous narrow IdentityProvisioner + a separate AppProvisioner that forced a
// runtime type-assert in the installer — no silent-degrade when wiring
// forgets a method.
type IdentityProvisioner interface {
	EnsureUser(ctx context.Context, email, displayName string) (pk string, created bool, err error)
	SetUserActive(ctx context.Context, pk string, active bool) error
	EnsureGroup(ctx context.Context, name string) (pk string, err error)
	EnsureAppOIDC(ctx context.Context, name, slug, redirectURI string) (authentik.AppOIDC, error)
	EnsureForwardAuth(ctx context.Context, name, slug, externalHost string) (authentik.AppOIDC, error)
}

type createOrgReq struct {
	Name string `json:"name"`
}

func (h *Handler) createOrganization(w http.ResponseWriter, r *http.Request) {
	if !rUser(r).IsAdmin {
		writeError(w, http.StatusForbidden, "forbidden", "platform admin required")
		return
	}
	var req createOrgReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	org, err := domain.NewOrganization(req.Name)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	created, err := h.d.IdentityStore.CreateOrganization(r.Context(), org)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "conflict", "organization name or slug already exists")
			return
		}
		h.internalError(w, err)
		return
	}
	h.audit(r.Context(), domain.AuditEvent{
		ActorUserID:  new(rUser(r).ID),
		Action:       "organization.created",
		ResourceType: "organization",
		ResourceID:   created.ID,
	})
	writeJSON(w, http.StatusCreated, created)
}

func (h *Handler) listOrganizations(w http.ResponseWriter, r *http.Request) {
	if !rUser(r).IsAdmin {
		writeError(w, http.StatusForbidden, "forbidden", "platform admin required")
		return
	}
	orgs, err := h.d.IdentityStore.ListOrganizations(r.Context(), 100)
	if err != nil {
		h.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, orgs)
}

type addMemberReq struct {
	UserID string         `json:"user_id"`
	Role   domain.OrgRole `json:"role"`
}

func (h *Handler) addOrganizationMember(w http.ResponseWriter, r *http.Request) {
	actor := rUser(r)
	orgID := r.PathValue("id")
	required := domain.RoleAdmin

	var req addMemberReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if !h.requireOrgRole(w, r, orgID, required) {
		return
	}
	// Only an owner may assign owner; only owner/admin assign admin.
	actorRole, err := h.d.IdentityStore.GetMembershipRole(r.Context(), orgID, actor.ID)
	if err != nil {
		h.internalError(w, err)
		return
	}
	if req.Role == domain.RoleOwner && !actorRole.CanManage(domain.RoleOwner) {
		writeError(w, http.StatusForbidden, "forbidden", "only an owner can grant owner")
		return
	}
	if req.Role == domain.RoleAdmin && !actorRole.CanManage(domain.RoleAdmin) {
		writeError(w, http.StatusForbidden, "forbidden", "only owner/admin can grant admin")
		return
	}
	m, err := h.d.IdentityStore.SetMembership(r.Context(), orgID, req.UserID, req.Role)
	if err != nil {
		h.internalError(w, err)
		return
	}
	h.audit(r.Context(), domain.AuditEvent{
		ActorUserID:  new(actor.ID),
		Action:       "organization.member_added",
		ResourceType: "organization",
		ResourceID:   orgID,
		Details:      map[string]any{"user_id": req.UserID, "role": string(req.Role)},
	})
	writeJSON(w, http.StatusOK, m)
}

func (h *Handler) listOrganizationMembers(w http.ResponseWriter, r *http.Request) {
	if !h.requireOrgRole(w, r, r.PathValue("id"), domain.RoleMember) {
		return
	}
	members, err := h.d.IdentityStore.ListMemberships(r.Context(), r.PathValue("id"))
	if err != nil {
		h.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, members)
}

type createGroupReq struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (h *Handler) createGroup(w http.ResponseWriter, r *http.Request) {
	orgID := r.PathValue("id")
	if !h.requireOrgRole(w, r, orgID, domain.RoleAdmin) {
		return
	}
	var req createGroupReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	g, err := domain.NewGroup(orgID, req.Name, req.Description)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	created, err := h.d.IdentityStore.CreateGroup(r.Context(), g)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "conflict", "group slug already exists in this organization")
			return
		}
		h.internalError(w, err)
		return
	}
	// Provision the mirror group in authentik and track the external id.
	if h.d.Identity != nil {
		pk, err := h.d.Identity.EnsureGroup(r.Context(), created.Slug)
		if err != nil {
			h.d.Logger.Warn("authentik group provisioning failed", "err", err)
		} else {
			_, _ = h.d.IdentityStore.UpsertExternalResource(r.Context(), domain.ExternalResource{
				ResourceType:     domain.ResTypeAuthentikGroup,
				PlatformObjectID: created.ID,
				Provider:         h.d.ProviderName,
				ExternalID:       pk,
				Status:           domain.ExtActive,
			})
		}
	}
	h.audit(r.Context(), domain.AuditEvent{
		ActorUserID:  new(rUser(r).ID),
		Action:       "group.created",
		ResourceType: "group",
		ResourceID:   created.ID,
	})
	writeJSON(w, http.StatusCreated, created)
}

func (h *Handler) listGroups(w http.ResponseWriter, r *http.Request) {
	if !h.requireOrgRole(w, r, r.PathValue("id"), domain.RoleMember) {
		return
	}
	groups, err := h.d.IdentityStore.ListGroupsByOrg(r.Context(), r.PathValue("id"))
	if err != nil {
		h.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, groups)
}

func (h *Handler) addGroupMember(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID string `json:"user_id"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	group, err := h.d.IdentityStore.GetGroupByID(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "group not found")
		return
	}
	if !h.requireOrgRole(w, r, group.OrganizationID, domain.RoleAdmin) {
		return
	}
	if err := h.d.IdentityStore.AddGroupMember(r.Context(), group.ID, req.UserID); err != nil {
		h.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *Handler) listGroupMembers(w http.ResponseWriter, r *http.Request) {
	group, err := h.d.IdentityStore.GetGroupByID(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "group not found")
		return
	}
	if !h.requireOrgRole(w, r, group.OrganizationID, domain.RoleMember) {
		return
	}
	members, err := h.d.IdentityStore.ListGroupMembers(r.Context(), group.ID)
	if err != nil {
		h.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, members)
}

type createUserReq struct {
	Email          string         `json:"email"`
	DisplayName    string         `json:"display_name"`
	OrganizationID string         `json:"organization_id"`
	GroupIDs       []string       `json:"group_ids"`
	Role           domain.OrgRole `json:"role"`
}

// createUser implements the add-user workflow (spec §79): platform user +
// authentik identity + org membership + groups; no mailbox is created.
func (h *Handler) createUser(w http.ResponseWriter, r *http.Request) {
	if !rUser(r).IsAdmin {
		writeError(w, http.StatusForbidden, "forbidden", "platform admin required")
		return
	}
	var req createUserReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if req.Email == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "email is required")
		return
	}
	if h.d.Identity == nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "identity provisioning unavailable")
		return
	}

	// 1. Provision the authentik identity first (idempotent by email).
	pk, _, err := h.d.Identity.EnsureUser(r.Context(), req.Email, req.DisplayName)
	if err != nil {
		h.d.Logger.Warn("authentik user provisioning failed", "err", err)
		writeError(w, http.StatusUnprocessableEntity, "provisioning_failed", "could not provision identity")
		return
	}

	// 2. Create the platform user linked to the authentik identity.
	user, err := h.d.IdentityStore.CreateUser(r.Context(), req.Email, req.DisplayName, h.d.ProviderName, pk)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "conflict", "user already exists")
			return
		}
		h.internalError(w, err)
		return
	}

	// 3. Record the external identity mapping.
	_, _ = h.d.IdentityStore.UpsertExternalResource(r.Context(), domain.ExternalResource{
		ResourceType:     domain.ResTypeAuthentikUser,
		PlatformObjectID: user.ID,
		Provider:         h.d.ProviderName,
		ExternalID:       pk,
		Status:           domain.ExtActive,
	})

	// 4. Org membership (if requested).
	if req.OrganizationID != "" {
		role := req.Role
		if role == "" || !role.Valid() {
			role = domain.RoleMember
		}
		if _, err := h.d.IdentityStore.SetMembership(r.Context(), req.OrganizationID, user.ID, role); err != nil {
			h.d.Logger.Warn("membership assignment failed", "err", err)
		}
		for _, gid := range req.GroupIDs {
			if err := h.d.IdentityStore.AddGroupMember(r.Context(), gid, user.ID); err != nil {
				h.d.Logger.Warn("group assignment failed", "err", err)
			}
		}
	}

	h.audit(r.Context(), domain.AuditEvent{
		ActorUserID:  new(rUser(r).ID),
		Action:       "user.created",
		ResourceType: "user",
		ResourceID:   user.ID,
		Details:      map[string]any{"email": user.Email, "authentik_id": pk},
	})
	writeJSON(w, http.StatusCreated, user)
}

func (h *Handler) disableUser(w http.ResponseWriter, r *http.Request) {
	if !rUser(r).IsAdmin {
		writeError(w, http.StatusForbidden, "forbidden", "platform admin required")
		return
	}
	id := r.PathValue("id")
	// Fetch the external id to disable the authentik identity (spec §80).
	res, err := h.d.IdentityStore.GetExternalResource(r.Context(), domain.ResTypeAuthentikUser, id)
	if err != nil {
		// Fall back to still disabling the platform user even if mapping missing.
		h.d.Logger.Warn("external mapping missing for user disable", "err", err, "user_id", id)
	}

	// 1. Disable authentik identity.
	if h.d.Identity != nil && err == nil {
		if derr := h.d.Identity.SetUserActive(r.Context(), res.ExternalID, false); derr != nil {
			h.d.Logger.Warn("authentik disable failed", "err", derr)
		}
	}
	// 2. Disable the platform user.
	if err := h.d.IdentityStore.SetUserStatus(r.Context(), id, domain.UserStatusDisabled); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "user not found")
			return
		}
		h.internalError(w, err)
		return
	}
	// 3. Strip org memberships and group memberships (spec §80 step 3-4).
	if err := h.d.IdentityStore.RemoveAllMemberships(r.Context(), id); err != nil {
		h.d.Logger.Warn("remove memberships on disable failed", "err", err)
	}
	if err := h.d.IdentityStore.RemoveAllGroupMemberships(r.Context(), id); err != nil {
		h.d.Logger.Warn("remove group memberships on disable failed", "err", err)
	}

	h.audit(r.Context(), domain.AuditEvent{
		ActorUserID:  new(rUser(r).ID),
		Action:       "user.disabled",
		ResourceType: "user",
		ResourceID:   id,
	})
	writeJSON(w, http.StatusOK, map[string]any{"status": "disabled"})
}

func (h *Handler) listUsers(w http.ResponseWriter, r *http.Request) {
	if !rUser(r).IsAdmin {
		writeError(w, http.StatusForbidden, "forbidden", "platform admin required")
		return
	}
	users, err := h.d.IdentityStore.ListUsers(r.Context(), 100)
	if err != nil {
		h.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, users)
}

func (h *Handler) requireOrgRole(w http.ResponseWriter, r *http.Request, orgID string, required domain.OrgRole) bool {
	u := rUser(r)
	if u.IsAdmin {
		return true
	}
	role, err := h.d.IdentityStore.GetMembershipRole(r.Context(), orgID, u.ID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusForbidden, "forbidden", "not a member of this organization")
		} else {
			h.internalError(w, err)
		}
		return false
	}
	if !role.CanManage(required) {
		writeError(w, http.StatusForbidden, "forbidden", "insufficient role")
		return false
	}
	return true
}

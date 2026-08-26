package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"selfu/internal/auth"
	"selfu/internal/authentik"
	"selfu/internal/domain"
	"selfu/internal/store"
)

// InviteStore persists single-use invite tokens tying an organization
// membership grant to first-login password setup.
type InviteStore interface {
	CreateInvite(ctx context.Context, inv store.Invite) (store.Invite, error)
	// ExpirePendingInvites burns every unconsumed invite for the org/user
	// pair so a re-invite supersedes older links.
	ExpirePendingInvites(ctx context.Context, orgID, userID string) error
	GetInviteByTokenHash(ctx context.Context, tokenHash string) (store.Invite, error)
	// ConsumeInvite marks the invite accepted atomically: it succeeds exactly
	// once per token and reports store.ErrConflict on replay or expiry.
	ConsumeInvite(ctx context.Context, id string) (store.Invite, error)
}

// PasswordSetter sets an external identity user's password (authentik).
type PasswordSetter interface {
	SetUserPassword(ctx context.Context, pk, password string) error
}

// The authentik admin client is the production password seam.
var _ PasswordSetter = (*authentik.Client)(nil)

// inviteTTL is how long an invite link stays redeemable.
const inviteTTL = 7 * 24 * time.Hour

// minInvitePasswordLen is the floor for self-set passwords.
const minInvitePasswordLen = 8

type createInviteReq struct {
	Email       string         `json:"email"`
	DisplayName string         `json:"display_name"`
	Role        domain.OrgRole `json:"role"`
}

type inviteResp struct {
	ID        string         `json:"id"`
	Role      domain.OrgRole `json:"role"`
	ExpiresAt time.Time      `json:"expires_at"`
	Token     string         `json:"token,omitempty"` // shown once; only the hash is stored
	Note      string         `json:"note,omitempty"`
}

type createInviteResp struct {
	User   domain.User `json:"user"`
	Invite inviteResp  `json:"invite"`
}

// createInvite issues a single-use invite token for a (possibly new) user.
// Unlike onboard-user it grants no mailbox secret and no membership yet: the
// membership lands when the invitee redeems the token and sets their own
// password on first login.
func (h *Handler) createInvite(w http.ResponseWriter, r *http.Request) {
	orgID := r.PathValue("id")
	actor := rUser(r)
	if !h.requireOrgRole(w, r, orgID, domain.RoleAdmin) {
		return
	}
	var req createInviteReq
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
	// Only an owner may invite someone with the owner role (same rule as
	// onboard-user). Platform admins are superusers via requireOrgRole.
	if role == domain.RoleOwner && !actor.IsAdmin {
		actorRole, err := h.d.IdentityStore.GetMembershipRole(r.Context(), orgID, actor.ID)
		if err != nil || !actorRole.CanManage(domain.RoleOwner) {
			writeError(w, http.StatusForbidden, "forbidden", "only an owner can invite with the owner role")
			return
		}
	}

	user, _, uerr := h.ensurePlatformUser(r.Context(), req.Email, req.DisplayName)
	if uerr != nil {
		h.internalError(w, uerr)
		return
	}

	// An existing member needs no invitation.
	if _, merr := h.d.IdentityStore.GetMembershipRole(r.Context(), orgID, user.ID); merr == nil {
		writeError(w, http.StatusConflict, "conflict", "user is already a member of this organization")
		return
	}

	// Re-inviting supersedes any pending link for this org/user pair.
	if err := h.d.Invites.ExpirePendingInvites(r.Context(), orgID, user.ID); err != nil {
		h.internalError(w, err)
		return
	}
	token, terr := auth.RandomToken(32)
	if terr != nil {
		h.internalError(w, terr)
		return
	}
	invitedBy := actor.ID
	inv, cerr := h.d.Invites.CreateInvite(r.Context(), store.Invite{
		ID:             uuid.NewString(),
		OrganizationID: orgID,
		UserID:         user.ID,
		TokenHash:      hashInviteToken(token),
		Role:           role,
		InvitedBy:      invitedBy,
		ExpiresAt:      time.Now().Add(inviteTTL),
	})
	if cerr != nil {
		h.internalError(w, cerr)
		return
	}

	h.audit(r.Context(), domain.AuditEvent{
		ActorUserID:  &invitedBy,
		Action:       "user.invited",
		ResourceType: "organization",
		ResourceID:   orgID,
		Details: map[string]any{
			"email":     user.Email,
			"user_id":   user.ID,
			"role":      string(role),
			"invite_id": inv.ID,
		},
	})
	writeJSON(w, http.StatusOK, createInviteResp{
		User: user,
		Invite: inviteResp{
			ID:        inv.ID,
			Role:      role,
			ExpiresAt: inv.ExpiresAt,
			Token:     token,
			Note:      "shown once; share it with the user over a trusted channel",
		},
	})
}

type acceptInviteReq struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

// acceptInvite redeems a single-use invite token: the invitee sets their own
// password upstream in authentik and claims their membership. The token is
// the credential, so this endpoint requires no session — exactly like the
// unauthenticated setup-login route. The invite is consumed atomically only
// after the password landed, so a failed attempt never burns the token.
func (h *Handler) acceptInvite(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req acceptInviteReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	tok := strings.TrimSpace(req.Token)
	if tok == "" || len(req.Password) < minInvitePasswordLen {
		writeError(w, http.StatusBadRequest, "invalid_request",
			"a valid invite token and a password of at least "+
				strconv.Itoa(minInvitePasswordLen)+" characters are required")
		return
	}
	inv, err := h.d.Invites.GetInviteByTokenHash(ctx, hashInviteToken(tok))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusBadRequest, "invalid_invite", "invite is invalid, expired or already used")
		return
	} else if err != nil {
		h.internalError(w, err)
		return
	}
	if inv.AcceptedAt != nil || time.Now().After(inv.ExpiresAt) {
		writeError(w, http.StatusBadRequest, "invalid_invite", "invite is invalid, expired or already used")
		return
	}

	// The external identity must exist so the password lands somewhere the
	// OIDC login can use.
	res, rerr := h.d.IdentityStore.GetExternalResource(ctx, domain.ResTypeAuthentikUser, inv.UserID)
	if rerr != nil || res.ExternalID == "" {
		writeError(w, http.StatusServiceUnavailable, "password_unavailable",
			"no external identity is linked to this user yet; ask an admin to re-invite later")
		return
	}
	if h.d.PasswordSetter == nil {
		writeError(w, http.StatusServiceUnavailable, "password_unavailable", "password setup is not configured")
		return
	}
	if serr := h.d.PasswordSetter.SetUserPassword(ctx, res.ExternalID, req.Password); serr != nil {
		h.d.Logger.Error("invite password set failed", "err", serr)
		writeError(w, http.StatusBadGateway, "password_set_failed",
			"could not set the password upstream; the invite was not consumed, try again")
		return
	}

	consumed, cerr := h.d.Invites.ConsumeInvite(ctx, inv.ID)
	if errors.Is(cerr, store.ErrConflict) {
		writeError(w, http.StatusConflict, "invite_used", "invite was already redeemed")
		return
	} else if cerr != nil {
		h.internalError(w, cerr)
		return
	}

	// Membership lands here — before acceptance the invitee has no access.
	membership, merr := h.d.IdentityStore.SetMembership(ctx, consumed.OrganizationID, consumed.UserID, consumed.Role)
	if merr != nil {
		h.internalError(w, merr)
		return
	}

	h.audit(ctx, domain.AuditEvent{
		Action:       "user.activated",
		ResourceType: "user",
		ResourceID:   consumed.UserID,
		Details: map[string]any{
			"organization_id": consumed.OrganizationID,
			"organization":    membership.OrganizationID,
			"role":            string(consumed.Role),
			"invite_id":       consumed.ID,
		},
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":              true,
		"organization_id": consumed.OrganizationID,
		"role":            consumed.Role,
	})
}

// ensurePlatformUser upserts the platform user by email, mirroring the
// onboard-user creation path (external identity provisioning best-effort so
// reconciliation repairs failures later).
func (h *Handler) ensurePlatformUser(ctx context.Context, email, displayName string) (domain.User, bool, error) {
	user, uerr := h.d.IdentityStore.GetUserByEmail(ctx, email)
	newUser := false
	if errors.Is(uerr, store.ErrNotFound) {
		pk := ""
		if h.d.Identity != nil {
			p, _, perr := h.d.Identity.EnsureUser(ctx, email, displayName)
			if perr != nil {
				h.d.Logger.Warn("authentik user provisioning failed", "err", perr)
			} else {
				pk = p
			}
		}
		user, uerr = h.d.IdentityStore.CreateUser(ctx, email, displayName, h.d.ProviderName, pk)
		if uerr != nil {
			return domain.User{}, false, uerr
		}
		newUser = true
		if pk != "" {
			if _, err := h.d.IdentityStore.UpsertExternalResource(ctx, domain.ExternalResource{
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
		return domain.User{}, false, uerr
	}
	return user, newUser, nil
}

func hashInviteToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

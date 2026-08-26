package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"selfu/internal/domain"
)

// Invite is a single-use invitation token tying an organization membership
// grant to first-login password setup. Only TokenHash is persisted — never
// the raw token.
type Invite struct {
	ID             string
	OrganizationID string
	UserID         string
	TokenHash      string
	Role           domain.OrgRole
	InvitedBy      string
	ExpiresAt      time.Time
	AcceptedAt     *time.Time
	CreatedAt      time.Time
}

const inviteColumns = `id, organization_id, user_id, token_hash, role, invited_by,
	expires_at, accepted_at, created_at`

const createInviteSQL = `
INSERT INTO invite_tokens (id, organization_id, user_id, token_hash, role, invited_by, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING ` + inviteColumns

// CreateInvite inserts a new invitation row.
func (s *Store) CreateInvite(ctx context.Context, inv Invite) (Invite, error) {
	if inv.ID == "" {
		inv.ID = uuid.NewString()
	}
	row := s.pool.QueryRow(ctx, createInviteSQL,
		inv.ID, inv.OrganizationID, inv.UserID, inv.TokenHash,
		string(inv.Role), inv.InvitedBy, inv.ExpiresAt)
	err := row.Scan(&inv.ID, &inv.OrganizationID, &inv.UserID, &inv.TokenHash,
		(*string)(&inv.Role), &inv.InvitedBy, &inv.ExpiresAt, &inv.AcceptedAt, &inv.CreatedAt)
	if err != nil {
		return Invite{}, fmt.Errorf("create invite: %w", err)
	}
	return inv, nil
}

const expirePendingInvitesSQL = `
UPDATE invite_tokens SET accepted_at = now()
WHERE organization_id = $1 AND user_id = $2 AND accepted_at IS NULL`

// ExpirePendingInvites burns every unconsumed invite for the pair so a
// re-invite supersedes older links.
func (s *Store) ExpirePendingInvites(ctx context.Context, orgID, userID string) error {
	if _, err := s.pool.Exec(ctx, expirePendingInvitesSQL, orgID, userID); err != nil {
		return fmt.Errorf("expire pending invites: %w", err)
	}
	return nil
}

const getInviteByTokenHashSQL = `
SELECT ` + inviteColumns + ` FROM invite_tokens WHERE token_hash = $1`

// GetInviteByTokenHash returns the invite for a token hash (present or past).
func (s *Store) GetInviteByTokenHash(ctx context.Context, tokenHash string) (Invite, error) {
	var inv Invite
	row := s.pool.QueryRow(ctx, getInviteByTokenHashSQL, tokenHash)
	err := row.Scan(&inv.ID, &inv.OrganizationID, &inv.UserID, &inv.TokenHash,
		(*string)(&inv.Role), &inv.InvitedBy, &inv.ExpiresAt, &inv.AcceptedAt, &inv.CreatedAt)
	if err != nil {
		if isNoRows(err) {
			return Invite{}, ErrNotFound
		}
		return Invite{}, fmt.Errorf("get invite by token hash: %w", err)
	}
	return inv, nil
}

const consumeInviteSQL = `
UPDATE invite_tokens SET accepted_at = now()
WHERE id = $1 AND accepted_at IS NULL AND expires_at > now()
RETURNING ` + inviteColumns

// ConsumeInvite marks the invite accepted atomically: it succeeds exactly
// once per token and reports ErrConflict on replay or expiry.
func (s *Store) ConsumeInvite(ctx context.Context, id string) (Invite, error) {
	var inv Invite
	row := s.pool.QueryRow(ctx, consumeInviteSQL, id)
	err := row.Scan(&inv.ID, &inv.OrganizationID, &inv.UserID, &inv.TokenHash,
		(*string)(&inv.Role), &inv.InvitedBy, &inv.ExpiresAt, &inv.AcceptedAt, &inv.CreatedAt)
	if err != nil {
		if isNoRows(err) {
			return Invite{}, ErrConflict
		}
		return Invite{}, fmt.Errorf("consume invite: %w", err)
	}
	return inv, nil
}

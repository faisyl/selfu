package store

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"selfu/internal/domain"
)

// CreateUser inserts an admin-created platform user linked to an external
// identity (authentik) whose external id is passed in authIdentityID. The
// user is born active; no mail identity is created (spec §79, step 5).
func (s *Store) CreateUser(ctx context.Context, email, displayName, authProvider, authIdentityID string) (domain.User, error) {
	id := uuid.NewString()
	email = strings.ToLower(strings.TrimSpace(email))
	displayName = strings.TrimSpace(displayName)
	var u domain.User
	err := s.pool.QueryRow(ctx, insertUserSQL,
		id, email, displayName, authProvider, authIdentityID).
		Scan(&u.ID, &u.Email, &u.DisplayName, &u.Status, &u.IsAdmin,
			&u.AuthProvider, &u.AuthIdentityID, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		if isUnique(err) {
			return domain.User{}, ErrConflict
		}
		return domain.User{}, fmt.Errorf("create user: %w", err)
	}
	return u, nil
}

// GetUserByEmail returns a user by normalized email.
func (s *Store) GetUserByEmail(ctx context.Context, email string) (domain.User, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	var u domain.User
	err := scanUser(s.pool.QueryRow(ctx, userByEmailSQL, email), &u, nil)
	if err != nil {
		return domain.User{}, mapNotFound(err, "user")
	}
	return u, nil
}

// SetUserStatus sets a user's lifecycle status (active/disabled).
func (s *Store) SetUserStatus(ctx context.Context, id string, status domain.UserStatus) error {
	if !status.Valid() {
		return fmt.Errorf("invalid user status %q", status)
	}
	tag, err := s.pool.Exec(ctx, setUserStatusSQL, string(status), id)
	if err != nil {
		return fmt.Errorf("set user status: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetUserAdmin grants or revokes platform-level admin.
func (s *Store) SetUserAdmin(ctx context.Context, id string, admin bool) error {
	_, err := s.pool.Exec(ctx, setUserAdminSQL, admin, id)
	if err != nil {
		return fmt.Errorf("set user admin: %w", err)
	}
	return nil
}

// ListUsers returns up to limit users ordered by email.
func (s *Store) ListUsers(ctx context.Context, limit int) ([]domain.User, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, listUsersSQL, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.User
	for rows.Next() {
		var u domain.User
		if err := scanUser(rows, &u, nil); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

const insertUserSQL = `
INSERT INTO users (id, email, display_name, status, is_admin, auth_provider, auth_identity_id)
VALUES ($1, $2, $3, 'active', false, $4, $5)
RETURNING id, email, display_name, status, is_admin, auth_provider, auth_identity_id, created_at, updated_at`

const userByEmailSQL = `
SELECT id, email, display_name, status, is_admin, auth_provider, auth_identity_id, created_at, updated_at
FROM users WHERE email = $1`

const setUserStatusSQL = `UPDATE users SET status = $1, updated_at = now() WHERE id = $2`

const setUserAdminSQL = `UPDATE users SET is_admin = $1, updated_at = now() WHERE id = $2`

const listUsersSQL = `
SELECT id, email, display_name, status, is_admin, auth_provider, auth_identity_id, created_at, updated_at
FROM users ORDER BY email LIMIT $1`

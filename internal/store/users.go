package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"selfu/internal/domain"
)

// UpsertFromOIDC inserts or reactivates the user identified by the given
// provider subject. Returns the stored user, whether the row was newly
// created, and whether the user was granted admin (bootstrap rule: the
// first user while no admin exists becomes an admin, spec §101; role
// management arrives with Phase 2).
func (s *Store) UpsertFromOIDC(
	ctx context.Context,
	provider, subject, email, displayName string,
) (domain.User, bool, bool, error) {
	user, err := domain.NewUser(email, displayName, provider, subject)
	if err != nil {
		return domain.User{}, false, false, err
	}
	user.ID = uuid.NewString()

	var inserted bool
	row := s.pool.QueryRow(ctx, upsertUserSQL,
		user.ID, user.Email, user.DisplayName, user.AuthProvider, user.AuthIdentityID)
	if err := scanUser(row, &user, &inserted); err != nil {
		return domain.User{}, false, false, fmt.Errorf("upsert user: %w", err)
	}

	adminGranted := false
	if inserted {
		err := s.pool.QueryRow(ctx, grantAdminIfNoneSQL, user.ID).Scan(&adminGranted)
		if err != nil {
			return domain.User{}, false, false, fmt.Errorf("bootstrap admin: %w", err)
		}
		user.IsAdmin = adminGranted
	}
	return user, inserted, adminGranted, nil
}

// GetByID returns the user with the given ID.
func (s *Store) GetByID(ctx context.Context, id string) (domain.User, error) {
	var user domain.User
	err := scanUser(s.pool.QueryRow(ctx, getUserByIDSQL, id), &user, nil)
	if err != nil {
		if isNoRows(err) {
			return domain.User{}, ErrNotFound
		}
		return domain.User{}, fmt.Errorf("get user: %w", err)
	}
	return user, nil
}

const upsertUserSQL = `
INSERT INTO users (id, email, display_name, status, auth_provider, auth_identity_id)
VALUES ($1, $2, $3, 'active', $4, $5)
ON CONFLICT (email)
DO UPDATE SET auth_provider = EXCLUDED.auth_provider,
              auth_identity_id = EXCLUDED.auth_identity_id,
              display_name = EXCLUDED.display_name,
              status = 'active',
              updated_at = now()
RETURNING id, email, display_name, status, is_admin,
          auth_provider, auth_identity_id, created_at, updated_at,
          (xmax = 0) AS inserted`

const grantAdminIfNoneSQL = `
UPDATE users SET is_admin = true, updated_at = now()
WHERE id = $1
  AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id <> users.id AND u.is_admin)
RETURNING is_admin`

const getUserByIDSQL = `
SELECT id, email, display_name, status, is_admin,
       auth_provider, auth_identity_id, created_at, updated_at
FROM users WHERE id = $1`

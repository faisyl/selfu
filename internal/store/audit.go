package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"selfu/internal/domain"
)

// CreateAuditEvent persists one audit event. Never log secrets or message
// content (spec §68, §69); Details is JSON metadata only.
func (s *Store) CreateAuditEvent(ctx context.Context, e domain.AuditEvent) error {
	if !e.Valid() {
		return fmt.Errorf("invalid audit event action %q", e.Action)
	}
	if e.Details == nil {
		e.Details = map[string]any{}
	}
	_, err := s.pool.Exec(ctx, insertAuditEventSQL,
		e.ID, e.ActorUserID, e.Action, e.ResourceType, e.ResourceID, e.Details, e.RequestID)
	if err != nil {
		return fmt.Errorf("insert audit event: %w", err)
	}
	return nil
}

// ListAuditEvents returns the most recent audit events (UI, §68). When
// actionFilter is non-empty only events whose action contains it (case-
// insensitive) are returned.
func (s *Store) ListAuditEvents(ctx context.Context, limit int, actionFilter string) ([]domain.AuditEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, listAuditEventsSQL, limit, actionFilter)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.AuditEvent
	for rows.Next() {
		var e domain.AuditEvent
		var details []byte
		if err := rows.Scan(&e.ID, &e.OccurredAt, &e.ActorUserID, &e.Action, &e.ResourceType,
			&e.ResourceID, &details, &e.RequestID); err != nil {
			return nil, err
		}
		if len(details) > 0 {
			_ = json.Unmarshal(details, &e.Details)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

const listAuditEventsSQL = `
SELECT id, occurred_at, actor_user_id, action, resource_type, resource_id, details, request_id
FROM audit_events
WHERE ($2 = '' OR action ILIKE '%' || $2 || '%')
ORDER BY occurred_at DESC LIMIT $1`
const insertAuditEventSQL = `
INSERT INTO audit_events (id, actor_user_id, action, resource_type, resource_id, details, request_id)
VALUES ($1, $2, $3, $4, $5, $6, $7)`

// scanUser scans a user row into u. When insertPtr is non-nil, the final
// column is scanned as a boolean into it.
func scanUser(row pgx.Row, u *domain.User, insertPtr *bool) error {
	var id, email, display, provider, identity string
	var status domain.UserStatus
	var isAdmin bool
	var createdAt, updatedAt time.Time
	var inserted bool

	dest := []any{&id, &email, &display, &status, &isAdmin,
		&provider, &identity, &createdAt, &updatedAt}
	if insertPtr != nil {
		dest = append(dest, &inserted)
	}
	if err := row.Scan(dest...); err != nil {
		return err
	}

	u.ID = id
	u.Email = email
	u.DisplayName = display
	u.Status = status
	u.IsAdmin = isAdmin
	u.AuthProvider = provider
	u.AuthIdentityID = identity
	u.CreatedAt = createdAt
	u.UpdatedAt = updatedAt
	if insertPtr != nil {
		*insertPtr = inserted
	}
	return nil
}

// isNoRows reports whether err is PostgreSQL's no-rows sentinel, also when
// wrapped.
func isNoRows(err error) bool {
	return errors.Is(err, pgx.ErrNoRows)
}

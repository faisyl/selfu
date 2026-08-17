package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"selfu/internal/domain"
)

// CreateGroup inserts an organization-scoped group.
func (s *Store) CreateGroup(ctx context.Context, g domain.Group) (domain.Group, error) {
	if g.ID == "" {
		g.ID = uuid.NewString()
	}
	err := s.pool.QueryRow(ctx, insertGroupSQL,
		g.ID, g.OrganizationID, g.Name, g.Slug, g.Description).
		Scan(&g.ID, &g.OrganizationID, &g.Name, &g.Slug, &g.Description, &g.CreatedAt, &g.UpdatedAt)
	if err != nil {
		if isUnique(err) {
			return domain.Group{}, ErrConflict
		}
		return domain.Group{}, fmt.Errorf("create group: %w", err)
	}
	return g, nil
}

// GetGroupByID returns a group by id.
func (s *Store) GetGroupByID(ctx context.Context, id string) (domain.Group, error) {
	var g domain.Group
	err := s.pool.QueryRow(ctx, groupByIDSQL, id).
		Scan(&g.ID, &g.OrganizationID, &g.Name, &g.Slug, &g.Description, &g.CreatedAt, &g.UpdatedAt)
	if err != nil {
		return domain.Group{}, mapNotFound(err, "group")
	}
	return g, nil
}

// ListGroupsByOrg returns groups in an organization.
func (s *Store) ListGroupsByOrg(ctx context.Context, orgID string) ([]domain.Group, error) {
	rows, err := s.pool.Query(ctx, listGroupsSQL, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Group
	for rows.Next() {
		var g domain.Group
		if err := rows.Scan(&g.ID, &g.OrganizationID, &g.Name, &g.Slug, &g.Description, &g.CreatedAt, &g.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// DeleteGroup removes a group.
func (s *Store) DeleteGroup(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, deleteGroupSQL, id)
	if err != nil {
		return fmt.Errorf("delete group: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// AddGroupMember adds a user to a group; existing membership is a no-op.
func (s *Store) AddGroupMember(ctx context.Context, groupID, userID string) error {
	_, err := s.pool.Exec(ctx, insertGroupMemberSQL, groupID, userID)
	if err != nil {
		if isUnique(err) {
			return nil // already a member
		}
		return fmt.Errorf("add group member: %w", err)
	}
	return nil
}

// RemoveGroupMember removes a user from a group.
func (s *Store) RemoveGroupMember(ctx context.Context, groupID, userID string) error {
	_, err := s.pool.Exec(ctx, deleteGroupMemberSQL, groupID, userID)
	if err != nil {
		return fmt.Errorf("remove group member: %w", err)
	}
	return nil
}

// GroupMember is a group membership joined with the user's identity.
type GroupMember struct {
	UserID      string
	Email       string
	DisplayName string
}

// RemoveAllGroupMemberships removes the user from every group.
func (s *Store) RemoveAllGroupMemberships(ctx context.Context, userID string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM group_memberships WHERE user_id = $1`, userID)
	if err != nil {
		return fmt.Errorf("remove all group memberships: %w", err)
	}
	return nil
}

// ListGroupMembers returns the users in a group.
func (s *Store) ListGroupMembers(ctx context.Context, groupID string) ([]GroupMember, error) {
	rows, err := s.pool.Query(ctx, listGroupMembersSQL, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GroupMember
	for rows.Next() {
		var m GroupMember
		if err := rows.Scan(&m.UserID, &m.Email, &m.DisplayName); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

const insertGroupSQL = `
INSERT INTO groups (id, organization_id, name, slug, description)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, organization_id, name, slug, description, created_at, updated_at`

const groupByIDSQL = `
SELECT id, organization_id, name, slug, description, created_at, updated_at FROM groups WHERE id = $1`

const listGroupsSQL = `
SELECT id, organization_id, name, slug, description, created_at, updated_at
FROM groups WHERE organization_id = $1 ORDER BY name`

const deleteGroupSQL = `DELETE FROM groups WHERE id = $1`

const insertGroupMemberSQL = `
INSERT INTO group_memberships (group_id, user_id) VALUES ($1, $2)
ON CONFLICT DO NOTHING`

const deleteGroupMemberSQL = `DELETE FROM group_memberships WHERE group_id = $1 AND user_id = $2`

const listGroupMembersSQL = `
SELECT u.id, u.email, u.display_name
FROM group_memberships gm JOIN users u ON u.id = gm.user_id
WHERE gm.group_id = $1 ORDER BY u.email`

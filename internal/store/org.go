package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"selfu/internal/domain"
)

// CreateOrganization inserts a new organization.
func (s *Store) CreateOrganization(ctx context.Context, o domain.Organization) (domain.Organization, error) {
	if o.ID == "" {
		o.ID = uuid.NewString()
	}
	err := s.pool.QueryRow(ctx, insertOrgSQL,
		o.ID, o.Name, o.Slug).Scan(&o.ID, &o.Name, &o.Slug, &o.Status, &o.CreatedAt, &o.UpdatedAt)
	if err != nil {
		if isUnique(err) {
			return domain.Organization{}, ErrConflict
		}
		return domain.Organization{}, fmt.Errorf("create organization: %w", err)
	}
	return o, nil
}

// GetOrganizationByID returns an organization by id.
func (s *Store) GetOrganizationByID(ctx context.Context, id string) (domain.Organization, error) {
	var o domain.Organization
	err := s.pool.QueryRow(ctx, orgByIDSQL, id).
		Scan(&o.ID, &o.Name, &o.Slug, &o.Status, &o.CreatedAt, &o.UpdatedAt)
	if err != nil {
		return domain.Organization{}, mapNotFound(err, "organization")
	}
	return o, nil
}

// ListOrganizations returns up to limit organizations ordered by name.
func (s *Store) ListOrganizations(ctx context.Context, limit int) ([]domain.Organization, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, listOrgsSQL, limit)
	if err != nil {
		return nil, fmt.Errorf("list organizations: %w", err)
	}
	defer rows.Close()

	var out []domain.Organization
	for rows.Next() {
		var o domain.Organization
		if err := rows.Scan(&o.ID, &o.Name, &o.Slug, &o.Status, &o.CreatedAt, &o.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// DeleteOrganization removes an organization and (cascades) its membership
// and group rows.
func (s *Store) DeleteOrganization(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, deleteOrgSQL, id)
	if err != nil {
		return fmt.Errorf("delete organization: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Member is an organization membership joined with the user's identity.
type Member struct {
	MembershipID string
	UserID       string
	Email        string
	DisplayName  string
	Role         domain.OrgRole
}

// SetMembership inserts the user into the organization with the given role
// (upsert) (spec §7).
func (s *Store) SetMembership(ctx context.Context, orgID, userID string, role domain.OrgRole) (domain.OrganizationMembership, error) {
	if role == "" {
		role = domain.RoleMember
	}
	if !role.Valid() {
		return domain.OrganizationMembership{}, fmt.Errorf("invalid role %q", role)
	}
	id := uuid.NewString()
	m := domain.OrganizationMembership{ID: id, OrganizationID: orgID, UserID: userID, Role: role}
	err := s.pool.QueryRow(ctx, upsertMembershipSQL,
		id, orgID, userID, string(role)).Scan(&m.Role, &m.CreatedAt)
	if err != nil {
		return domain.OrganizationMembership{}, fmt.Errorf("set membership: %w", err)
	}
	return m, nil
}

// GetMembershipRole returns the user's role in the organization.
func (s *Store) GetMembershipRole(ctx context.Context, orgID, userID string) (domain.OrgRole, error) {
	var role string
	err := s.pool.QueryRow(ctx, membershipRoleSQL, orgID, userID).Scan(&role)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", err
	}
	return domain.OrgRole(role), nil
}

// ListMemberships returns all members of an organization.
func (s *Store) ListMemberships(ctx context.Context, orgID string) ([]Member, error) {
	rows, err := s.pool.Query(ctx, listMembershipsSQL, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Member
	for rows.Next() {
		var m Member
		var role string
		if err := rows.Scan(&m.MembershipID, &m.UserID, &m.Email, &m.DisplayName, &role); err != nil {
			return nil, err
		}
		m.Role = domain.OrgRole(role)
		out = append(out, m)
	}
	return out, rows.Err()
}

// RemoveMembership removes the user from the organization.
func (s *Store) RemoveMembership(ctx context.Context, orgID, userID string) error {
	_, err := s.pool.Exec(ctx, removeMembershipSQL, orgID, userID)
	if err != nil {
		return fmt.Errorf("remove membership: %w", err)
	}
	return nil
}

// RemoveAllMemberships removes the user from every organization.
func (s *Store) RemoveAllMemberships(ctx context.Context, userID string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM organization_memberships WHERE user_id = $1`, userID)
	if err != nil {
		return fmt.Errorf("remove all memberships: %w", err)
	}
	return nil
}

// ListOrganizationsForUser returns the roles the user holds across orgs.
func (s *Store) ListOrganizationsForUser(ctx context.Context, userID string) ([]domain.Organization, error) {
	rows, err := s.pool.Query(ctx, listOrgsForUserSQL, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Organization
	for rows.Next() {
		var o domain.Organization
		if err := rows.Scan(&o.ID, &o.Name, &o.Slug, &o.Status, &o.CreatedAt, &o.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

const insertOrgSQL = `
INSERT INTO organizations (id, name, slug) VALUES ($1, $2, $3)
RETURNING id, name, slug, status, created_at, updated_at`

const orgByIDSQL = `
SELECT id, name, slug, status, created_at, updated_at FROM organizations WHERE id = $1`

const listOrgsSQL = `
SELECT id, name, slug, status, created_at, updated_at FROM organizations ORDER BY name LIMIT $1`

const deleteOrgSQL = `DELETE FROM organizations WHERE id = $1`

const upsertMembershipSQL = `
INSERT INTO organization_memberships (id, organization_id, user_id, role)
VALUES ($1, $2, $3, $4)
ON CONFLICT (organization_id, user_id)
DO UPDATE SET role = EXCLUDED.role
RETURNING role, created_at`

const membershipRoleSQL = `
SELECT role FROM organization_memberships WHERE organization_id = $1 AND user_id = $2`

const listMembershipsSQL = `
SELECT om.id, om.user_id, u.email, u.display_name, om.role
FROM organization_memberships om
JOIN users u ON u.id = om.user_id
WHERE om.organization_id = $1
ORDER BY u.email`

const removeMembershipSQL = `
DELETE FROM organization_memberships WHERE organization_id = $1 AND user_id = $2`

const listOrgsForUserSQL = `
SELECT o.id, o.name, o.slug, o.status, o.created_at, o.updated_at
FROM organizations o
JOIN organization_memberships om ON om.organization_id = o.id
WHERE om.user_id = $1
ORDER BY o.name`

// mapNotFound converts pgx no-rows into ErrNotFound with a context label.
func mapNotFound(err error, what string) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return fmt.Errorf("%s: %w", what, err)
}

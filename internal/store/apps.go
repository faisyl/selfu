package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"selfu/internal/catalog"
)

// CreateCatalogApp registers a validated catalog entry.
func (s *Store) CreateCatalogApp(ctx context.Context, m *catalog.Manifest) (string, error) {
	id := uuid.NewString()
	raw, _ := json.Marshal(m)
	_, err := s.pool.Exec(ctx, insertCatalogAppSQL,
		id, m.Metadata.Name, m.ID, m.Version, m.Metadata.Description, m.Metadata.Category, raw)
	if err != nil {
		if isUnique(err) {
			return "", ErrConflict
		}
		return "", fmt.Errorf("create catalog app: %w", err)
	}
	return id, nil
}

// GetCatalogAppByID returns a catalog entry by id.
func (s *Store) GetCatalogAppByID(ctx context.Context, id string) (CatalogApp, error) {
	var a CatalogApp
	var raw []byte
	err := s.pool.QueryRow(ctx, catalogAppByIDSQL, id).
		Scan(&a.ID, &a.Name, &a.Slug, &a.Version, &a.Description, &a.Category, &raw)
	if err != nil {
		return CatalogApp{}, mapNotFound(err, "catalog app")
	}
	_ = json.Unmarshal(raw, &a.Manifest)
	return a, nil
}

// ListCatalogApps returns the catalog.
func (s *Store) ListCatalogApps(ctx context.Context) ([]CatalogApp, error) {
	rows, err := s.pool.Query(ctx, listCatalogAppsSQL)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CatalogApp
	for rows.Next() {
		var a CatalogApp
		var raw []byte
		if err := rows.Scan(&a.ID, &a.Name, &a.Slug, &a.Version, &a.Description, &a.Category, &raw); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(raw, &a.Manifest)
		out = append(out, a)
	}
	return out, rows.Err()
}

// CreateApplicationInstance creates a pending instance.
func (s *Store) CreateApplicationInstance(ctx context.Context, orgID, catalogID, name, slug string) (string, error) {
	id := uuid.NewString()
	_, err := s.pool.Exec(ctx, insertInstanceSQL, id, orgID, catalogID, name, slug)
	if err != nil {
		return "", fmt.Errorf("create instance: %w", err)
	}
	return id, nil
}

// SetInstanceStatus updates an instance lifecycle status.
func (s *Store) SetInstanceStatus(ctx context.Context, id, status string) error {
	_, err := s.pool.Exec(ctx, setInstanceStatusSQL, status, id)
	if err != nil {
		return fmt.Errorf("set instance status: %w", err)
	}
	return nil
}

// GetInstance returns an instance.
func (s *Store) GetInstance(ctx context.Context, id string) (Instance, error) {
	var in Instance
	err := s.pool.QueryRow(ctx, instanceByIDSQL, id).
		Scan(&in.ID, &in.OrganizationID, &in.CatalogID, &in.Name, &in.Slug, &in.Status, &in.CreatedAt, &in.UpdatedAt)
	if err != nil {
		return Instance{}, mapNotFound(err, "instance")
	}
	return in, nil
}

// ListInstancesByOrg returns an org's instances.
func (s *Store) ListInstancesByOrg(ctx context.Context, orgID string) ([]Instance, error) {
	rows, err := s.pool.Query(ctx, listInstancesSQL, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Instance
	for rows.Next() {
		var in Instance
		if err := rows.Scan(&in.ID, &in.OrganizationID, &in.CatalogID, &in.Name, &in.Slug, &in.Status, &in.CreatedAt, &in.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, in)
	}
	return out, rows.Err()
}

// AddInstanceHostname binds a hostname to an instance.
func (s *Store) AddInstanceHostname(ctx context.Context, instanceID, hostname string) error {
	_, err := s.pool.Exec(ctx, insertAppHostnameSQL, uuid.NewString(), instanceID, hostname)
	if err != nil {
		if isUnique(err) {
			return ErrConflict
		}
		return fmt.Errorf("add instance hostname: %w", err)
	}
	return nil
}

// AddInstanceAccessGroup grants a group access to an instance (spec §17).
func (s *Store) AddInstanceAccessGroup(ctx context.Context, instanceID, groupID string) error {
	_, err := s.pool.Exec(ctx, insertAccessGroupSQL, instanceID, groupID)
	if err != nil {
		if isUnique(err) {
			return nil
		}
		return fmt.Errorf("add instance access group: %w", err)
	}
	return nil
}

// CatalogApp is a stored catalog entry.
type CatalogApp struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Slug        string            `json:"slug"`
	Version     string            `json:"version"`
	Description string            `json:"description"`
	Category    string            `json:"category"`
	Manifest    *catalog.Manifest `json:"manifest"`
}

// Instance is a provisioned application instance.
type Instance struct {
	ID             string `json:"id"`
	OrganizationID string `json:"organization_id"`
	CatalogID      string `json:"catalog_id"`
	Name           string `json:"name"`
	Slug           string `json:"slug"`
	Status         string `json:"status"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
}

const insertCatalogAppSQL = `
INSERT INTO catalog_applications (id, name, slug, version, description, category, manifest)
VALUES ($1, $2, $3, $4, $5, $6, $7)`

const catalogAppByIDSQL = `
SELECT id, name, slug, version, description, category, manifest
FROM catalog_applications WHERE id = $1`

const listCatalogAppsSQL = `
SELECT id, name, slug, version, description, category, manifest
FROM catalog_applications ORDER BY name`

const insertInstanceSQL = `
INSERT INTO application_instances (id, organization_id, catalog_id, name, slug)
VALUES ($1, $2, $3, $4, $5)`

const setInstanceStatusSQL = `UPDATE application_instances SET status = $1, updated_at = now() WHERE id = $2`

const instanceByIDSQL = `
SELECT id, organization_id, catalog_id, name, slug, status, created_at::text, updated_at::text
FROM application_instances WHERE id = $1`

const listInstancesSQL = `
SELECT id, organization_id, catalog_id, name, slug, status, created_at::text, updated_at::text
FROM application_instances WHERE organization_id = $1 ORDER BY name`

const insertAppHostnameSQL = `
INSERT INTO application_hostnames (id, application_instance_id, hostname)
VALUES ($1, $2, $3)`

const insertAccessGroupSQL = `
INSERT INTO application_access_groups (application_instance_id, group_id) VALUES ($1, $2)
ON CONFLICT DO NOTHING`

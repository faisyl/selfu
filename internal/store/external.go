package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"selfu/internal/domain"
)

// UpsertExternalResource records a platform object's external counterpart,
// keyed by (resource_type, platform_object_id) (spec §22). External ids are
// stored explicitly, never inferred from names (spec §16).
func (s *Store) UpsertExternalResource(ctx context.Context, res domain.ExternalResource) (domain.ExternalResource, error) {
	if res.ID == "" {
		res.ID = uuid.NewString()
	}
	if res.Status == "" {
		res.Status = domain.ExtProvisioning
	}
	err := s.pool.QueryRow(ctx, upsertExternalSQL,
		res.ID, res.ResourceType, res.PlatformObjectID, res.Provider,
		res.ExternalID, res.Status).
		Scan(&res.ID, &res.ResourceType, &res.PlatformObjectID, &res.Provider,
			&res.ExternalID, &res.Status, &res.CreatedAt, &res.UpdatedAt)
	if err != nil {
		return domain.ExternalResource{}, fmt.Errorf("upsert external resource: %w", err)
	}
	return res, nil
}

// GetExternalResource returns the mapping for a platform object.
func (s *Store) GetExternalResource(ctx context.Context, resourceType, platformObjectID string) (domain.ExternalResource, error) {
	var res domain.ExternalResource
	err := s.pool.QueryRow(ctx, externalByObjectSQL, resourceType, platformObjectID).
		Scan(&res.ID, &res.ResourceType, &res.PlatformObjectID, &res.Provider,
			&res.ExternalID, &res.Status, &res.CreatedAt, &res.UpdatedAt)
	if err != nil {
		return domain.ExternalResource{}, mapNotFound(err, "external resource")
	}
	return res, nil
}

// ListExternalResourcesByProvider returns all mappings for a provider.
func (s *Store) ListExternalResourcesByProvider(ctx context.Context, provider string) ([]domain.ExternalResource, error) {
	rows, err := s.pool.Query(ctx, listExternalByProviderSQL, provider)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.ExternalResource
	for rows.Next() {
		var res domain.ExternalResource
		if err := rows.Scan(&res.ID, &res.ResourceType, &res.PlatformObjectID, &res.Provider,
			&res.ExternalID, &res.Status, &res.CreatedAt, &res.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, rows.Err()
}

// SetExternalObserved records the observed state + hash of a mapping
// (spec §22).
func (s *Store) SetExternalObserved(ctx context.Context, id, status, observedHash, lastErr string) error {
	_, err := s.pool.Exec(ctx, setExternalObservedSQL, status, observedHash, lastErr, id)
	if err != nil {
		return fmt.Errorf("set external observed: %w", err)
	}
	return nil
}

// SetExternalStatus updates the observed status of an external resource.
func (s *Store) SetExternalStatus(ctx context.Context, id, status, lastErr string) error {
	_, err := s.pool.Exec(ctx, setExternalStatusSQL, status, lastErr, id)
	if err != nil {
		return fmt.Errorf("set external status: %w", err)
	}
	return nil
}

// ListExternalResources returns mappings for a platform object (any type).
func (s *Store) ListExternalResources(ctx context.Context, platformObjectID string) ([]domain.ExternalResource, error) {
	rows, err := s.pool.Query(ctx, listExternalSQL, platformObjectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.ExternalResource
	for rows.Next() {
		var res domain.ExternalResource
		if err := rows.Scan(&res.ID, &res.ResourceType, &res.PlatformObjectID, &res.Provider,
			&res.ExternalID, &res.Status, &res.CreatedAt, &res.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, rows.Err()
}

const upsertExternalSQL = `
INSERT INTO external_resources
    (id, resource_type, platform_object_id, provider, external_id, status)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (resource_type, platform_object_id)
DO UPDATE SET external_id = EXCLUDED.external_id,
              provider = EXCLUDED.provider,
              status = EXCLUDED.status,
              updated_at = now()
RETURNING id, resource_type, platform_object_id, provider, external_id, status, created_at, updated_at`

const externalByObjectSQL = `
SELECT id, resource_type, platform_object_id, provider, external_id, status, created_at, updated_at
FROM external_resources WHERE resource_type = $1 AND platform_object_id = $2`

const listExternalByProviderSQL = `
SELECT id, resource_type, platform_object_id, provider, external_id, status, created_at, updated_at
FROM external_resources WHERE provider = $1 ORDER BY resource_type`

const setExternalObservedSQL = `
UPDATE external_resources SET status = $1, observed_hash = $2, last_error = $3, updated_at = now()
WHERE id = $4`

const setExternalStatusSQL = `
UPDATE external_resources SET status = $1, last_error = $2, updated_at = now() WHERE id = $3`

const listExternalSQL = `
SELECT id, resource_type, platform_object_id, provider, external_id, status, created_at, updated_at
FROM external_resources WHERE platform_object_id = $1 ORDER BY resource_type`

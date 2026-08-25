package store

import (
	"context"
	"fmt"
	"time"

	"selfu/internal/domain"
)

// GetInstallation returns the singleton installation/onboarding row.
func (s *Store) GetInstallation(ctx context.Context) (domain.Installation, error) {
	var inst domain.Installation
	var primaryDomainID string
	err := s.pool.QueryRow(ctx, installationSQL).Scan(
		&inst.LocalDomain, &primaryDomainID, &inst.DNSProvider,
		&inst.AccessProvider, &inst.OnboardedAt, &inst.CreatedAt, &inst.UpdatedAt,
	)
	if err != nil {
		if isNoRows(err) {
			// The row is created by the migration; treat absence as a
			// fresh installation rather than a hard failure.
			return domain.Installation{
				LocalDomain:    domain.DefaultLocalDomain,
				DNSProvider:    "manual",
				AccessProvider: "manual",
			}, nil
		}
		return domain.Installation{}, fmt.Errorf("get installation: %w", err)
	}
	inst.PrimaryDomainID = primaryDomainID
	return inst, nil
}

// SetInstallationPrimaryDomain associates the verified primary domain with
// the installation (onboarding completion, spec §88).
func (s *Store) SetInstallationPrimaryDomain(ctx context.Context, domainID string) error {
	tag, err := s.pool.Exec(ctx, setInstallationPrimaryDomainSQL, domainID)
	if err != nil {
		return fmt.Errorf("set installation primary domain: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetInstallationProvider stores the configured DNS/access provider pair and
// its encrypted config.
func (s *Store) SetInstallationProvider(ctx context.Context, dnsProvider, accessProvider string, config []byte) error {
	tag, err := s.pool.Exec(ctx, setInstallationProviderSQL, dnsProvider, accessProvider, config)
	if err != nil {
		return fmt.Errorf("set installation provider: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// GetInstallationConfig returns the encrypted provider config blob.
func (s *Store) GetInstallationConfig(ctx context.Context) ([]byte, error) {
	var cfg []byte
	if err := s.pool.QueryRow(ctx, installationConfigSQL).Scan(&cfg); err != nil {
		if isNoRows(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get installation config: %w", err)
	}
	return cfg, nil
}

// SetInstallationOnboarded marks the wizard complete.
func (s *Store) SetInstallationOnboarded(ctx context.Context, at time.Time) error {
	if _, err := s.pool.Exec(ctx, setInstallationOnboardedSQL, at); err != nil {
		return fmt.Errorf("set installation onboarded: %w", err)
	}
	return nil
}

// ErrInstallationLocked is returned when mutating onboarding state that is
// already complete (the wizard is one-shot).

const installationSQL = `
SELECT local_domain, COALESCE(primary_domain_id::text, ''), dns_provider, access_provider,
       onboarded_at, created_at, updated_at
FROM installation WHERE id = TRUE`

const installationConfigSQL = `SELECT provider_config FROM installation WHERE id = TRUE`

const setInstallationPrimaryDomainSQL = `
UPDATE installation SET primary_domain_id = $1, updated_at = now() WHERE id = TRUE
  AND onboarded_at IS NULL`

const setInstallationProviderSQL = `
UPDATE installation
SET dns_provider = $1, access_provider = $2, provider_config = $3, updated_at = now()
WHERE id = TRUE AND onboarded_at IS NULL`

const setInstallationOnboardedSQL = `
UPDATE installation SET onboarded_at = $1, updated_at = now() WHERE id = TRUE
  AND onboarded_at IS NULL`

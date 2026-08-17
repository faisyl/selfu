package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"selfu/internal/domain"
)

// ErrHasDependents is returned when a resource cannot be deleted because
// dependent resources are still attached (spec §64).
var ErrHasDependents = errors.New("store: resource has dependents")

// CreateDomain inserts a domain in pending state with a fresh verification
// token (spec §11).
func (s *Store) CreateDomain(ctx context.Context, d domain.Domain) (domain.Domain, error) {
	if d.ID == "" {
		d.ID = uuid.NewString()
	}
	token, err := randomTokenHex(32)
	if err != nil {
		return domain.Domain{}, fmt.Errorf("verification token: %w", err)
	}
	d.Status = domain.DomainPending
	d.VerificationToken = token
	err = s.pool.QueryRow(ctx, insertDomainSQL,
		d.ID, d.OrganizationID, d.FQDN, string(d.Status),
		d.VerificationMethod, d.VerificationToken).
		Scan(&d.ID, &d.OrganizationID, &d.FQDN, &d.Status, &d.VerificationMethod,
			&d.VerificationToken, &d.VerifiedAt, &d.WebEnabled, &d.MailEnabled,
			&d.CreatedAt, &d.UpdatedAt)
	if err != nil {
		if isUnique(err) {
			return domain.Domain{}, ErrConflict
		}
		return domain.Domain{}, fmt.Errorf("create domain: %w", err)
	}
	return d, nil
}

// GetDomainByID returns a domain by id.
func (s *Store) GetDomainByID(ctx context.Context, id string) (domain.Domain, error) {
	var d domain.Domain
	err := scanDomain(s.pool.QueryRow(ctx, domainByIDSQL, id), &d)
	if err != nil {
		return domain.Domain{}, mapNotFound(err, "domain")
	}
	return d, nil
}

// GetDomainByOrgFQDN returns a domain for an organization and exact fqdn.
func (s *Store) GetDomainByOrgFQDN(ctx context.Context, orgID, fqdn string) (domain.Domain, error) {
	var d domain.Domain
	err := scanDomain(s.pool.QueryRow(ctx, domainByOrgFQDNSQL, orgID, fqdn), &d)
	if err != nil {
		return domain.Domain{}, mapNotFound(err, "domain")
	}
	return d, nil
}

// ListDomainsByOrg returns the organization's domains.
func (s *Store) ListDomainsByOrg(ctx context.Context, orgID string) ([]domain.Domain, error) {
	rows, err := s.pool.Query(ctx, listDomainsSQL, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Domain
	for rows.Next() {
		var d domain.Domain
		if err := scanDomain(rows, &d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// SetDomainStatus updates a domain's lifecycle status and verified_at.
func (s *Store) SetDomainStatus(ctx context.Context, id string, status domain.DomainStatus, verifiedAt *time.Time) error {
	if !status.Valid() {
		return fmt.Errorf("invalid domain status %q", status)
	}
	tag, err := s.pool.Exec(ctx, setDomainStatusSQL, string(status), verifiedAt, id)
	if err != nil {
		return fmt.Errorf("set domain status: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// LogVerification appends a verification attempt (spec §10/§11 audit trail).
func (s *Store) LogVerification(ctx context.Context, domainID, method, detail string, success bool) error {
	_, err := s.pool.Exec(ctx, insertVerificationSQL, uuid.NewString(), domainID, method, success, detail)
	if err != nil {
		return fmt.Errorf("log verification: %w", err)
	}
	return nil
}

// DeleteDomain removes a domain unless it still has hostnames (spec §64).
func (s *Store) DeleteDomain(ctx context.Context, id string) error {
	var n int
	if err := s.pool.QueryRow(ctx, countHostnamesSQL, id).Scan(&n); err != nil {
		return fmt.Errorf("check hostnames: %w", err)
	}
	if n > 0 {
		return ErrHasDependents
	}
	tag, err := s.pool.Exec(ctx, deleteDomainSQL, id)
	if err != nil {
		return fmt.Errorf("delete domain: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// AddHostname binds a hostname under a domain.
func (s *Store) AddHostname(ctx context.Context, h domain.Hostname) (domain.Hostname, error) {
	if h.ID == "" {
		h.ID = uuid.NewString()
	}
	h.Status = "active"
	err := s.pool.QueryRow(ctx, insertHostnameSQL,
		h.ID, h.DomainID, h.Hostname, h.Status).
		Scan(&h.ID, &h.DomainID, &h.ApplicationInstanceID, &h.Hostname, &h.Status, &h.CreatedAt, &h.UpdatedAt)
	if err != nil {
		if isUnique(err) {
			return domain.Hostname{}, ErrConflict
		}
		return domain.Hostname{}, fmt.Errorf("add hostname: %w", err)
	}
	return h, nil
}

// GetHostnameByID returns a hostname by id.
func (s *Store) GetHostnameByID(ctx context.Context, id string) (domain.Hostname, error) {
	var h domain.Hostname
	err := scanHostname(s.pool.QueryRow(ctx, hostnameByIDSQL, id), &h)
	if err != nil {
		return domain.Hostname{}, mapNotFound(err, "hostname")
	}
	return h, nil
}

// ListHostnamesByDomain returns the hostnames bound to a domain.
func (s *Store) ListHostnamesByDomain(ctx context.Context, domainID string) ([]domain.Hostname, error) {
	rows, err := s.pool.Query(ctx, listHostnamesSQL, domainID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Hostname
	for rows.Next() {
		var h domain.Hostname
		if err := scanHostname(rows, &h); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// RemoveHostname removes a hostname binding.
func (s *Store) RemoveHostname(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, deleteHostnameSQL, id)
	if err != nil {
		return fmt.Errorf("remove hostname: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func randomTokenHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func scanDomain(row pgxRow, d *domain.Domain) error {
	return row.Scan(&d.ID, &d.OrganizationID, &d.FQDN, &d.Status, &d.VerificationMethod,
		&d.VerificationToken, &d.VerifiedAt, &d.WebEnabled, &d.MailEnabled,
		&d.CreatedAt, &d.UpdatedAt)
}

func scanHostname(row pgxRow, h *domain.Hostname) error {
	return row.Scan(&h.ID, &h.DomainID, &h.ApplicationInstanceID, &h.Hostname, &h.Status,
		&h.CreatedAt, &h.UpdatedAt)
}

const insertDomainSQL = `
INSERT INTO domains
    (id, organization_id, fqdn, status, verification_method, verification_token)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id, organization_id, fqdn, status, verification_method, verification_token,
          verified_at, web_enabled, mail_enabled, created_at, updated_at`

const domainByIDSQL = `
SELECT id, organization_id, fqdn, status, verification_method, verification_token,
       verified_at, web_enabled, mail_enabled, created_at, updated_at
FROM domains WHERE id = $1`

const domainByOrgFQDNSQL = `
SELECT id, organization_id, fqdn, status, verification_method, verification_token,
       verified_at, web_enabled, mail_enabled, created_at, updated_at
FROM domains WHERE organization_id = $1 AND fqdn = $2`

const listDomainsSQL = `
SELECT id, organization_id, fqdn, status, verification_method, verification_token,
       verified_at, web_enabled, mail_enabled, created_at, updated_at
FROM domains WHERE organization_id = $1 ORDER BY fqdn`

const setDomainStatusSQL = `
UPDATE domains SET status = $1, verified_at = $2, updated_at = now() WHERE id = $3`

const countHostnamesSQL = `SELECT count(*) FROM hostnames WHERE domain_id = $1`

const deleteDomainSQL = `DELETE FROM domains WHERE id = $1`

const insertVerificationSQL = `
INSERT INTO domain_verifications (id, domain_id, method, success, detail)
VALUES ($1, $2, $3, $4, $5)`

const insertHostnameSQL = `
INSERT INTO hostnames (id, domain_id, hostname, status) VALUES ($1, $2, $3, $4)
RETURNING id, domain_id, application_instance_id, hostname, status, created_at, updated_at`

const hostnameByIDSQL = `
SELECT id, domain_id, application_instance_id, hostname, status, created_at, updated_at
FROM hostnames WHERE id = $1`

const listHostnamesSQL = `
SELECT id, domain_id, application_instance_id, hostname, status, created_at, updated_at
FROM hostnames WHERE domain_id = $1 ORDER BY hostname`

const deleteHostnameSQL = `DELETE FROM hostnames WHERE id = $1`

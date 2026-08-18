package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"selfu/internal/domain"
)

// CreateMailDomain records a mail-enabled platform domain.
func (s *Store) CreateMailDomain(ctx context.Context, domainID string) (domain.MailDomain, error) {
	var m domain.MailDomain
	err := s.pool.QueryRow(ctx, insertMailDomainSQL, uuid.NewString(), domainID).
		Scan(&m.ID, &m.DomainID, &m.Status, &m.Inbound, &m.Outbound, &m.TLS, &m.DKIM, &m.CreatedAt, &m.UpdatedAt)
	if err != nil {
		if isUnique(err) {
			return domain.MailDomain{}, ErrConflict
		}
		return domain.MailDomain{}, fmt.Errorf("create mail domain: %w", err)
	}
	return m, nil
}

// GetMailDomainByDomainID returns the mail domain for a platform domain.
func (s *Store) GetMailDomainByDomainID(ctx context.Context, domainID string) (domain.MailDomain, error) {
	var m domain.MailDomain
	err := scanMailDomain(s.pool.QueryRow(ctx, mailDomainByDomainSQL, domainID), &m)
	if err != nil {
		return domain.MailDomain{}, mapNotFound(err, "mail domain")
	}
	return m, nil
}

// SetMailDomainStatus updates a mail domain's lifecycle status.
func (s *Store) SetMailDomainStatus(ctx context.Context, id, status string) error {
	_, err := s.pool.Exec(ctx, setMailDomainStatusSQL, status, id)
	if err != nil {
		return fmt.Errorf("set mail domain status: %w", err)
	}
	return nil
}

// SetMailDomainDKIM stores the DKIM selector + DNS record and marks the
// domain's DKIM status configured (spec §28, §68).
func (s *Store) SetMailDomainDKIM(ctx context.Context, id, selector, record string) error {
	_, err := s.pool.Exec(ctx, setMailDomainDKIMSQL, selector, record, id)
	if err != nil {
		return fmt.Errorf("set mail domain dkim: %w", err)
	}
	return nil
}

// CreateMailIdentity inserts a mail identity (default status provisioning).
func (s *Store) CreateMailIdentity(ctx context.Context, m domain.MailIdentity) (domain.MailIdentity, error) {
	if m.ID == "" {
		m.ID = uuid.NewString()
	}
	err := s.pool.QueryRow(ctx, insertMailIdentitySQL,
		m.ID, m.OrganizationID, m.UserID, m.DomainID, m.LocalPart, m.Address, m.ChasquidUsername).
		Scan(&m.ID, &m.OrganizationID, &m.UserID, &m.DomainID, &m.LocalPart, &m.Address,
			&m.ChasquidUsername, &m.Status, &m.CreatedAt, &m.UpdatedAt)
	if err != nil {
		if isUnique(err) {
			return domain.MailIdentity{}, ErrConflict
		}
		return domain.MailIdentity{}, fmt.Errorf("create mail identity: %w", err)
	}
	return m, nil
}

// GetMailIdentity returns a mail identity by id.
func (s *Store) GetMailIdentity(ctx context.Context, id string) (domain.MailIdentity, error) {
	var m domain.MailIdentity
	err := scanMailIdentity(s.pool.QueryRow(ctx, mailIdentityByIDSQL, id), &m)
	if err != nil {
		return domain.MailIdentity{}, mapNotFound(err, "mail identity")
	}
	return m, nil
}

// GetMailIdentityByAddress returns a mail identity by full address.
func (s *Store) GetMailIdentityByAddress(ctx context.Context, address string) (domain.MailIdentity, error) {
	var m domain.MailIdentity
	err := scanMailIdentity(s.pool.QueryRow(ctx, mailIdentityByAddressSQL, address), &m)
	if err != nil {
		return domain.MailIdentity{}, mapNotFound(err, "mail identity")
	}
	return m, nil
}

// ListMailIdentitiesByDomain returns identities for a domain.
func (s *Store) ListMailIdentitiesByDomain(ctx context.Context, domainID string) ([]domain.MailIdentity, error) {
	rows, err := s.pool.Query(ctx, listMailIdentitiesSQL, domainID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.MailIdentity
	for rows.Next() {
		var m domain.MailIdentity
		if err := scanMailIdentity(rows, &m); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// SetMailIdentityStatus updates an identity lifecycle status.
func (s *Store) SetMailIdentityStatus(ctx context.Context, id, status string) error {
	_, err := s.pool.Exec(ctx, setMailIdentityStatusSQL, status, id)
	if err != nil {
		return fmt.Errorf("set mail identity status: %w", err)
	}
	return nil
}

// CreateMailCredential records a credential's fingerprint (spec §62).
func (s *Store) CreateMailCredential(ctx context.Context, c domain.MailCredential) (domain.MailCredential, error) {
	if c.ID == "" {
		c.ID = uuid.NewString()
	}
	err := s.pool.QueryRow(ctx, insertMailCredentialSQL,
		c.ID, c.MailIdentityID, c.SecretFingerprint).
		Scan(&c.ID, &c.MailIdentityID, &c.SecretFingerprint, &c.Status, &c.CreatedAt, &c.RotatedAt)
	if err != nil {
		return domain.MailCredential{}, fmt.Errorf("create mail credential: %w", err)
	}
	return c, nil
}

// RevokeCredentialsByIdentity revokes all active credentials of an identity.
func (s *Store) RevokeCredentialsByIdentity(ctx context.Context, identityID string) error {
	_, err := s.pool.Exec(ctx, revokeCredentialsSQL, identityID)
	if err != nil {
		return fmt.Errorf("revoke credentials: %w", err)
	}
	return nil
}

// CreateMailAlias inserts an alias (spec §37), optionally group-bound (§42).
func (s *Store) CreateMailAlias(ctx context.Context, a domain.MailAlias) (domain.MailAlias, error) {
	if a.ID == "" {
		a.ID = uuid.NewString()
	}
	dests, _ := json.Marshal(a.Destinations)
	err := s.pool.QueryRow(ctx, insertMailAliasSQL,
		a.ID, a.OrganizationID, a.DomainID, a.GroupID, a.LocalPart, a.Address, dests).
		Scan(&a.ID, &a.OrganizationID, &a.DomainID, &a.GroupID, &a.LocalPart, &a.Address, &dests, &a.Status, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		if isUnique(err) {
			return domain.MailAlias{}, ErrConflict
		}
		return domain.MailAlias{}, fmt.Errorf("create mail alias: %w", err)
	}
	_ = json.Unmarshal(dests, &a.Destinations)
	return a, nil
}

// UpdateMailAliasDestinations refreshes an alias's destination set.
func (s *Store) UpdateMailAliasDestinations(ctx context.Context, id string, destinations []string) error {
	dests, _ := json.Marshal(destinations)
	_, err := s.pool.Exec(ctx, updateMailAliasDestsSQL, dests, id)
	if err != nil {
		return fmt.Errorf("update mail alias destinations: %w", err)
	}
	return nil
}

// ListMailIdentitiesByUsers returns the ACTIVE mail identities of the given
// users within an organization (used for group aliases, §42–43).
func (s *Store) ListMailIdentitiesByUsers(ctx context.Context, orgID string, userIDs []string) ([]domain.MailIdentity, error) {
	if len(userIDs) == 0 {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, listMailIdentitiesByUsersSQL, orgID, userIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.MailIdentity
	for rows.Next() {
		var m domain.MailIdentity
		if err := scanMailIdentity(rows, &m); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// GetMailAliasByAddress returns an alias by full address (used for
// cross-organization validation, spec §39).
func (s *Store) GetMailAliasByAddress(ctx context.Context, address string) (domain.MailAlias, error) {
	var a domain.MailAlias
	err := scanMailAlias(s.pool.QueryRow(ctx, mailAliasByAddressSQL, address), &a)
	if err != nil {
		return domain.MailAlias{}, mapNotFound(err, "mail alias")
	}
	return a, nil
}

// ListMailAliasesByDomain returns aliases for a domain.
func (s *Store) ListMailAliasesByDomain(ctx context.Context, domainID string) ([]domain.MailAlias, error) {
	rows, err := s.pool.Query(ctx, listMailAliasesSQL, domainID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.MailAlias
	for rows.Next() {
		var a domain.MailAlias
		if err := scanMailAlias(rows, &a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// DeleteMailAlias removes an alias row.
func (s *Store) DeleteMailAlias(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, deleteMailAliasSQL, id)
	if err != nil {
		return fmt.Errorf("delete mail alias: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// CreateMailSubmissionPolicy records what a credential may send as (spec §49).
func (s *Store) CreateMailSubmissionPolicy(ctx context.Context, p domain.MailSubmissionPolicy) error {
	_, err := s.pool.Exec(ctx, insertMailPolicySQL,
		uuid.NewString(), p.MailIdentityID, p.CredentialID, arr(p.AllowedFromAddresses), arr(p.AllowedFromDomains), p.ApplicationInstanceID)
	if err != nil {
		return fmt.Errorf("create mail policy: %w", err)
	}
	return nil
}

func arr(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

func scanMailDomain(row pgxRow, m *domain.MailDomain) error {
	return row.Scan(&m.ID, &m.DomainID, &m.Status, &m.Inbound, &m.Outbound, &m.TLS, &m.DKIM, &m.CreatedAt, &m.UpdatedAt)
}

func scanMailIdentity(row pgxRow, m *domain.MailIdentity) error {
	return row.Scan(&m.ID, &m.OrganizationID, &m.UserID, &m.DomainID, &m.LocalPart, &m.Address,
		&m.ChasquidUsername, &m.Status, &m.CreatedAt, &m.UpdatedAt)
}

func scanMailAlias(row pgxRow, a *domain.MailAlias) error {
	var dests []byte
	if err := row.Scan(&a.ID, &a.OrganizationID, &a.DomainID, &a.GroupID, &a.LocalPart, &a.Address, &dests, &a.Status, &a.CreatedAt, &a.UpdatedAt); err != nil {
		return err
	}
	return json.Unmarshal(dests, &a.Destinations)
}

const insertMailDomainSQL = `
INSERT INTO mail_domains (id, domain_id) VALUES ($1, $2)
RETURNING id, domain_id, status, inbound_status, outbound_status, tls_status, dkim_status, created_at, updated_at`

const mailDomainByDomainSQL = `
SELECT id, domain_id, status, inbound_status, outbound_status, tls_status, dkim_status, created_at, updated_at
FROM mail_domains WHERE domain_id = $1`

const setMailDomainStatusSQL = `UPDATE mail_domains SET status = $1, updated_at = now() WHERE id = $2`

const setMailDomainDKIMSQL = `UPDATE mail_domains SET dkim_selector = $1, dkim_dns_record = $2, dkim_status = 'configured', updated_at = now() WHERE id = $3`

const insertMailIdentitySQL = `
INSERT INTO mail_identities (id, organization_id, user_id, domain_id, local_part, address, chasquid_username)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING id, organization_id, user_id, domain_id, local_part, address, chasquid_username, status, created_at, updated_at`

const mailIdentityByIDSQL = `
SELECT id, organization_id, user_id, domain_id, local_part, address, chasquid_username, status, created_at, updated_at
FROM mail_identities WHERE id = $1`

const mailIdentityByAddressSQL = `
SELECT id, organization_id, user_id, domain_id, local_part, address, chasquid_username, status, created_at, updated_at
FROM mail_identities WHERE address = $1`

const listMailIdentitiesSQL = `
SELECT id, organization_id, user_id, domain_id, local_part, address, chasquid_username, status, created_at, updated_at
FROM mail_identities WHERE domain_id = $1 ORDER BY address`

const setMailIdentityStatusSQL = `UPDATE mail_identities SET status = $1, updated_at = now() WHERE id = $2`

const insertMailCredentialSQL = `
INSERT INTO mail_credentials (id, mail_identity_id, secret_fingerprint) VALUES ($1, $2, $3)
RETURNING id, mail_identity_id, secret_fingerprint, status, created_at, rotated_at`

const revokeCredentialsSQL = `
UPDATE mail_credentials SET status = 'revoked', rotated_at = now() WHERE mail_identity_id = $1 AND status = 'active'`

const insertMailAliasSQL = `
INSERT INTO mail_aliases (id, organization_id, domain_id, group_id, local_part, address, destinations)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING id, organization_id, domain_id, group_id, local_part, address, destinations, status, created_at, updated_at`

const mailAliasByAddressSQL = `
SELECT id, organization_id, domain_id, group_id, local_part, address, destinations, status, created_at, updated_at
FROM mail_aliases WHERE address = $1`

const listMailAliasesSQL = `
SELECT id, organization_id, domain_id, group_id, local_part, address, destinations, status, created_at, updated_at
FROM mail_aliases WHERE domain_id = $1 ORDER BY address`

const updateMailAliasDestsSQL = `
UPDATE mail_aliases SET destinations = $1, updated_at = now() WHERE id = $2`

const listMailIdentitiesByUsersSQL = `
SELECT id, organization_id, user_id, domain_id, local_part, address, chasquid_username, status, created_at, updated_at
FROM mail_identities
WHERE organization_id = $1 AND user_id = ANY($2::uuid[]) AND status = 'active'
ORDER BY address`

const deleteMailAliasSQL = `DELETE FROM mail_aliases WHERE id = $1`

const insertMailPolicySQL = `
INSERT INTO mail_submission_policies
    (id, mail_identity_id, credential_id, allowed_from_addresses, allowed_from_domains, application_instance_id)
VALUES ($1, $2, $3, $4, $5, $6)`

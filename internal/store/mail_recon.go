package store

import "context"

// ActiveMailDomain joins a mail domain to its platform domain for the
// reconciliation worker (spec §66).
type ActiveMailDomain struct {
	MailDomainID   string
	DomainID       string
	OrganizationID string
	FQDN           string
}

// ListActiveMailDomains returns all active mail domains.
func (s *Store) ListActiveMailDomains(ctx context.Context) ([]ActiveMailDomain, error) {
	rows, err := s.pool.Query(ctx, listActiveMailDomainsSQL)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ActiveMailDomain
	for rows.Next() {
		var m ActiveMailDomain
		if err := rows.Scan(&m.MailDomainID, &m.DomainID, &m.OrganizationID, &m.FQDN); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

const listActiveMailDomainsSQL = `
SELECT md.id, md.domain_id, d.organization_id, d.fqdn
FROM mail_domains md
JOIN domains d ON d.id = md.domain_id
WHERE md.status = 'active'
ORDER BY d.fqdn`

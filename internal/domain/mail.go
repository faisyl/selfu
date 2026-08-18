package domain

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// MailDomain mirrors a verified platform domain used for mail (spec §26).
type MailDomain struct {
	ID        string    `json:"id"`
	DomainID  string    `json:"domain_id"`
	Status    string    `json:"status"`
	Inbound   string    `json:"inbound_status"`
	Outbound  string    `json:"outbound_status"`
	TLS       string    `json:"tls_status"`
	DKIM      string    `json:"dkim_status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ValidateLocalPart enforces the RFC 5321-ish "dot-atom" local part used by
// the platform (conservative subset: letters, digits, and ._-+).
func ValidateLocalPart(local string) error {
	local = strings.TrimSpace(local)
	if local == "" {
		return errors.New("local part is required")
	}
	if len(local) > 64 {
		return errors.New("local part too long")
	}
	for _, r := range local {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '.', r == '_', r == '-', r == '+':
		default:
			return fmt.Errorf("invalid character %q in local part", r)
		}
	}
	if strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") || strings.Contains(local, "..") {
		return errors.New("local part must not start/end with or contain consecutive dots")
	}
	return nil
}

// BuildAddress renders local_part@domain and checks the domain parses as a
// hostname.
func BuildAddress(localPart, fqdn string) (string, error) {
	if err := ValidateLocalPart(localPart); err != nil {
		return "", err
	}
	norm, err := NormalizeDomain(fqdn)
	if err != nil {
		return "", err
	}
	addr := strings.ToLower(localPart) + "@" + norm
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return "", errors.New("address must not contain a port")
	}
	return addr, nil
}

// MailIdentityStatus is the lifecycle of a mail identity (spec §32).
const (
	MailIdentityRequested    = "requested"
	MailIdentityProvisioning = "provisioning"
	MailIdentityActive       = "active"
	MailIdentitySuspended    = "suspended"
	MailIdentityDeleted      = "deleted"
)

// MailIdentity is an address+SMTP capability belonging to a platform user
// (spec §31).
type MailIdentity struct {
	ID               string    `json:"id"`
	OrganizationID   string    `json:"organization_id"`
	UserID           *string   `json:"user_id,omitempty"`
	DomainID         string    `json:"domain_id"`
	LocalPart        string    `json:"local_part"`
	Address          string    `json:"address"`
	ChasquidUsername string    `json:"chasquid_username"`
	Status           string    `json:"status"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// MailAlias forwards an address to destinations (spec §37); a group-bound
// alias derives destinations from the group's active identities (§42–43).
type MailAlias struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	DomainID       string    `json:"domain_id"`
	GroupID        *string   `json:"group_id,omitempty"`
	LocalPart      string    `json:"local_part"`
	Address        string    `json:"address"`
	Destinations   []string  `json:"destinations"`
	Status         string    `json:"status"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// MailCredential is the platform's record of an SMTP credential; the secret
// itself is shown once at creation and never stored (spec §36, §62).
type MailCredential struct {
	ID                string    `json:"id"`
	MailIdentityID    string    `json:"mail_identity_id"`
	SecretFingerprint string    `json:"-"`
	Status            string    `json:"status"`
	CreatedAt         time.Time `json:"created_at"`
	RotatedAt         time.Time `json:"rotated_at"`
}

// MailSubmissionPolicy binds a credential to the senders it may use
// (spec §49; enforced by the post-data hook). ApplicationInstanceID links
// the policy to an app instance for application SMTP credentials (§46).
type MailSubmissionPolicy struct {
	ID                    string   `json:"id"`
	MailIdentityID        string   `json:"mail_identity_id"`
	CredentialID          string   `json:"credential_id"`
	AllowedFromAddresses  []string `json:"allowed_from_addresses"`
	AllowedFromDomains    []string `json:"allowed_from_domains"`
	ApplicationInstanceID *string  `json:"application_instance_id,omitempty"`
}

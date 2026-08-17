package domain

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/net/idna"
)

// DomainStatus is the lifecycle of a domain (spec §10): pending →
// verification_required → verified (+web/mail enablement), or suspended.
type DomainStatus string

const (
	DomainPending              DomainStatus = "pending"
	DomainVerificationRequired DomainStatus = "verification_required"
	DomainVerified             DomainStatus = "verified"
	DomainSuspended            DomainStatus = "suspended"
)

// Valid reports whether s is a known domain status.
func (s DomainStatus) Valid() bool {
	switch s {
	case DomainPending, DomainVerificationRequired, DomainVerified, DomainSuspended:
		return true
	}
	return false
}

// Domain is a first-class resource shared by web and mail (spec §9).
type Domain struct {
	ID                 string       `json:"id"`
	OrganizationID     string       `json:"organization_id"`
	FQDN               string       `json:"fqdn"`
	Status             DomainStatus `json:"status"`
	VerificationMethod string       `json:"verification_method"`
	VerificationToken  string       `json:"verification_token"`
	VerifiedAt         *time.Time   `json:"verified_at,omitempty"`
	WebEnabled         bool         `json:"web_enabled"`
	MailEnabled        bool         `json:"mail_enabled"`
	CreatedAt          time.Time    `json:"created_at"`
	UpdatedAt          time.Time    `json:"updated_at"`
}

// NormalizeDomain validates and normalizes an internationalized domain name
// to ASCII (punycode), lowercase, without a trailing dot.
func NormalizeDomain(s string) (string, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return "", errors.New("domain is required")
	}
	if len(s) > 253 {
		return "", errors.New("domain is too long")
	}
	ascii, err := idna.Lookup.ToASCII(s)
	if err != nil {
		return "", fmt.Errorf("invalid internationalized domain: %w", err)
	}
	ascii = strings.ToLower(ascii)
	for _, label := range strings.Split(ascii, ".") {
		if label == "" {
			return "", errors.New("domain has an empty label")
		}
		if len(label) > 63 {
			return "", errors.New("domain label exceeds 63 characters")
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if c == '-' {
				if i == 0 || i == len(label)-1 {
					return "", errors.New("domain label must not start or end with a hyphen")
				}
				continue
			}
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') {
				return "", errors.New("invalid character in domain label")
			}
		}
	}
	return ascii, nil
}

// NewDomain validates and creates a placeholder domain awaiting ownership
// verification.
func NewDomain(organizationID, fqdn string) (Domain, error) {
	norm, err := NormalizeDomain(fqdn)
	if err != nil {
		return Domain{}, err
	}
	if organizationID == "" {
		return Domain{}, errors.New("organization id is required")
	}
	return Domain{
		OrganizationID:     organizationID,
		FQDN:               norm,
		Status:             DomainPending,
		VerificationMethod: "dns_txt",
	}, nil
}

// HostnameWithinDomain reports whether hostname is contained within domain
// using label boundaries — never a naive string suffix (spec §12). That is,
// "git.example.com" is within "example.com" but "notexample.com" and
// "example.com.attacker.io" are not.
func HostnameWithinDomain(hostname, domainName string) bool {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(hostname)), ".")
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domainName)), ".")
	if h == "" || d == "" {
		return false
	}
	if h == d {
		return true
	}
	return strings.HasSuffix(h, "."+d)
}

// Hostname is a public application hostname bound to a verified domain
// (spec §12).
type Hostname struct {
	ID                    string    `json:"id"`
	DomainID              string    `json:"domain_id"`
	ApplicationInstanceID *string   `json:"application_instance_id,omitempty"`
	Hostname              string    `json:"hostname"`
	Status                string    `json:"status"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
}

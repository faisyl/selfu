package domain

import (
	"strings"
	"time"
)

// DefaultLocalDomain is the local domain the platform serves before any
// public primary domain is onboarded (selfu.local).
const DefaultLocalDomain = "selfu.local"

// Installation is the platform's onboarding state (spec §88). It is a
// singleton: one row, never deleted, created by the first migration.
type Installation struct {
	// LocalDomain is the private/local domain (selfu.local by default).
	LocalDomain string `json:"local_domain"`
	// PrimaryDomainID references the verified primary domain associated
	// with the installation; empty until onboarding completes.
	PrimaryDomainID string `json:"primary_domain_id,omitempty"`
	// DNSProvider and AccessProvider are the configured provider
	// identifiers ("manual" or "cloudflare").
	DNSProvider    string `json:"dns_provider"`
	AccessProvider string `json:"access_provider"`
	// OnboardedAt is set when the wizard completes; nil while pending.
	OnboardedAt *time.Time `json:"onboarded_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// Onboarded reports whether the installation completed the bootstrap wizard.
func (i Installation) Onboarded() bool {
	return i.OnboardedAt != nil
}

// ValidateLocalDomain normalizes the local domain, falling back to the
// default when empty.
func ValidateLocalDomain(s string) string {
	if s = strings.TrimSpace(s); s == "" {
		return DefaultLocalDomain
	}
	return strings.ToLower(s)
}

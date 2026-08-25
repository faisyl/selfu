package access

import (
	"context"
	"fmt"

	"selfu/internal/dns"
)

// manualDNS is the manual DNS surface: it never auto-writes and instead
// returns copy-paste instructions as the error. It still wraps
// dns.ErrManual so callers using errors.Is keep treating manual as a
// non-automated provider (the setup wizard reports automated=false when
// SetTXT fails).
type manualDNS struct{}

// Name matches the "manual" provider identifier.
func (manualDNS) Name() string { return "manual" }

// SetTXT reports the TXT record the operator must add by hand.
func (manualDNS) SetTXT(_ context.Context, fqdn, value string) error {
	return fmt.Errorf("%w: create a TXT record named %s with value %q",
		dns.ErrManual, fqdn, value)
}

// RemoveTXT reports the TXT record the operator must remove by hand.
func (manualDNS) RemoveTXT(_ context.Context, fqdn, value string) error {
	return fmt.Errorf("%w: remove the TXT record named %s with value %q",
		dns.ErrManual, fqdn, value)
}

// SetAddr reports the A record the operator must add by hand.
func (manualDNS) SetAddr(_ context.Context, fqdn, ip string) error {
	return fmt.Errorf("%w: create an A record named %s pointing at %q",
		dns.ErrManual, fqdn, ip)
}

// RemoveAddr reports the A record the operator must remove by hand.
func (manualDNS) RemoveAddr(_ context.Context, fqdn, ip string) error {
	return fmt.Errorf("%w: remove the A record named %s pointing at %q",
		dns.ErrManual, fqdn, ip)
}

// AutomatedReporter lets callers ask whether a provider writes DNS
// records itself. Providers may implement it; manual does not automate.
type AutomatedReporter interface {
	Automated() bool
}

var _ dns.Provider = manualDNS{}

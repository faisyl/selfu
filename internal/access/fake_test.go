package access

import (
	"context"

	"selfu/internal/dns"
)

// Fake records every provisioning call for assertions in handler tests.
type Fake struct {
	// Provider is the delegated provider (manual by default).
	Provider Provider
	// TXTSet and TXTRemoved record SetTXT/RemoveTXT calls.
	TXTSet      []string
	TXTRemoved  []string
	AddrSet     []string
	AddrRemoved []string
	// ValidateErr makes Validate fail (provider config rejection).
	ValidateErr error
}

// NewFake returns a fake access provider that delegates to manual.
func NewFake() *Fake {
	return &Fake{Provider: NewManual()}
}

// Name is the fake provider identifier.
func (f *Fake) Name() string { return "fake" }

// DNS returns the fake's own DNS surface (records calls).
func (f *Fake) DNS() dns.Provider { return f }

// ACME is empty for the fake.
func (f *Fake) ACME() string { return "" }

// ResolveZone delegates to the wrapped provider (manual returns "").
func (f *Fake) ResolveZone(ctx context.Context, domain string) (string, error) {
	return f.Provider.ResolveZone(ctx, domain)
}

// Validate returns the configured error, if any.
func (f *Fake) Validate(_ context.Context) error { return f.ValidateErr }

// SetTXT records the call and delegates.
func (f *Fake) SetTXT(ctx context.Context, fqdn, value string) error {
	f.TXTSet = append(f.TXTSet, fqdn)
	return f.Provider.DNS().SetTXT(ctx, fqdn, value)
}

// RemoveTXT records the call and delegates.
func (f *Fake) RemoveTXT(ctx context.Context, fqdn, value string) error {
	f.TXTRemoved = append(f.TXTRemoved, fqdn)
	return f.Provider.DNS().RemoveTXT(ctx, fqdn, value)
}

// SetAddr records the call and delegates.
func (f *Fake) SetAddr(ctx context.Context, fqdn, ip string) error {
	f.AddrSet = append(f.AddrSet, fqdn)
	return f.Provider.DNS().SetAddr(ctx, fqdn, ip)
}

// RemoveAddr records the call and delegates.
func (f *Fake) RemoveAddr(ctx context.Context, fqdn, ip string) error {
	f.AddrRemoved = append(f.AddrRemoved, fqdn)
	return f.Provider.DNS().RemoveAddr(ctx, fqdn, ip)
}

// dnsRecorder is the DNS surface of the fake; it satisfies both
// access.Provider.DNS and dns.Provider.
type dnsRecorder interface {
	SetTXT(ctx context.Context, fqdn, value string) error
	RemoveTXT(ctx context.Context, fqdn, value string) error
	SetAddr(ctx context.Context, fqdn, ip string) error
	RemoveAddr(ctx context.Context, fqdn, ip string) error
}

// Compile-time assertions.
var _ Provider = (*Fake)(nil)
var _ dns.Provider = (*Fake)(nil)

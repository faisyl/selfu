package access

import (
	"context"
	"errors"

	"selfu/internal/dns"
)

// Cloudflare is the Cloudflare external-access provider: it publishes DNS
// records (TXT verification + A records) via the Cloudflare API v4 and
// emits a Traefik DNS-01 ACME resolver using the same credentials.
type Cloudflare struct {
	dns  dns.Provider
	cfg  Config
	acme string
}

// NewCloudflare builds the Cloudflare access provider.
func NewCloudflare(cfg Config, opts ...Option) *Cloudflare {
	o := &options{}
	for _, opt := range opts {
		opt(o)
	}
	return &Cloudflare{
		dns: dns.NewCloudflare(dns.CloudflareConfig{
			APIToken: cfg.APIToken,
			ZoneID:   cfg.ZoneID,
			BaseURL:  o.baseURL,
		}),
		cfg:  cfg,
		acme: ACMEChallengeFor("cloudflare", cfg),
	}
}

// Name matches the "cloudflare" provider identifier.
func (c *Cloudflare) Name() string { return "cloudflare" }

// DNS is the Cloudflare DNS surface.
func (c *Cloudflare) DNS() dns.Provider { return c.dns }

// ACME is the DNS-01 resolver configuration for Traefik.
func (c *Cloudflare) ACME() string { return c.acme }

// Validate checks the zone is reachable with the configured credentials.
func (c *Cloudflare) Validate(ctx context.Context) error {
	if zone, ok := c.dns.(*dns.CloudflareProvider); ok {
		return zone.ZoneExists(ctx)
	}
	return nil
}

// ResolveZone looks up the Cloudflare zone id for the domain using the
// configured API token.
func (c *Cloudflare) ResolveZone(ctx context.Context, domain string) (string, error) {
	zone, ok := c.dns.(*dns.CloudflareProvider)
	if !ok {
		return "", errors.New("access: cloudflare dns provider unavailable")
	}
	return zone.ZoneIDByDomain(ctx, domain)
}

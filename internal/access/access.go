// Package access provides the external-access provider abstraction (spec
// §59, §88): a provider manages both the DNS records that publish a
// platform hostname (TXT verification + origin A records) and the ACME
// challenge configuration that secures it (DNS-01). Providers are selected
// by identifier and registered through New; manual is the no-op default.
package access

import (
	"context"
	"errors"
	"fmt"

	"selfu/internal/dns"
)

// Provider is the external-access seam. It composes the DNS record surface
// with the ACME challenge configuration emitted to the ingress (Traefik).
type Provider interface {
	// Name is the provider identifier ("manual", "cloudflare").
	Name() string
	// DNS is the DNS record surface used for verification and A records.
	DNS() dns.Provider
	// ACME renders the DNS-01 challenge configuration consumed by the
	// ingress (Traefik certificatesResolvers). It is empty for providers
	// that use HTTP-01 or do not manage DNS.
	ACME() string
	// ResolveZone derives the provider's zone identifier from a domain
	// using its own credentials, so onboarding needs only a domain + token.
	// Manual returns an empty zone without error.
	ResolveZone(ctx context.Context, domain string) (string, error)
	// Validate checks that the provider configuration is usable (e.g.
	// the Cloudflare zone is reachable). Manual always passes.
	Validate(ctx context.Context) error
}

// Manual is the no-op provider: DNS records are added by hand and ACME
// falls back to the ingress default.
type Manual struct{}

// NewManual returns the manual access provider.
func NewManual() *Manual { return &Manual{} }

// Name matches the "manual" provider identifier.
func (Manual) Name() string { return "manual" }

// DNS is the manual DNS surface (never auto-provisions; emits
// instructions).
func (Manual) DNS() dns.Provider { return manualDNS{} }

// Automated reports that this provider never writes records itself.
func (Manual) Automated() bool { return false }

// ACME emits no challenge configuration.
func (Manual) ACME() string { return "" }

// ResolveZone returns an empty zone (no provider to query).
func (Manual) ResolveZone(context.Context, string) (string, error) { return "", nil }

// Validate always passes for manual provisioning.
func (Manual) Validate(context.Context) error { return nil }

// Config carries credentials for an automated access provider. Sensitive
// fields must never be logged.
type Config struct {
	APIToken string `json:"api_token"`
	ZoneID   string `json:"zone_id"`

	// AWS credentials for the route53 provider (hosted zone id reuses
	// ZoneID). When empty they fall back to the standard environment
	// variables AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,
	// AWS_SESSION_TOKEN and AWS_REGION.
	AWSAccessKeyID     string `json:"aws_access_key_id,omitempty"`
	AWSSecretAccessKey string `json:"aws_secret_access_key,omitempty"`
	AWSSessionToken    string `json:"aws_session_token,omitempty"`
	AWSRegion          string `json:"aws_region,omitempty"`
}

// ErrUnknownProvider is returned when a provider identifier is not
// registered.
var ErrUnknownProvider = errors.New("access: unknown provider")

// New builds the provider named name. cloudflare and route53 require
// provider credentials (see their constructors); manual ignores cfg.
func New(name string, cfg Config, opts ...Option) (Provider, error) {
	switch name {
	case "manual":
		return NewManual(), nil
	case "cloudflare":
		return NewCloudflare(cfg, opts...), nil
	case "route53":
		return NewRoute53(cfg, opts...), nil
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnknownProvider, name)
	}
}

// Option configures a provider (test overrides).
type Option func(*options)

type options struct {
	baseURL string
	route53 route53API
}

// WithBaseURL overrides the Cloudflare API base URL (testing).
func WithBaseURL(base string) Option {
	return func(o *options) { o.baseURL = base }
}

// WithRoute53Client injects the AWS Route 53 seam (testing; no live calls
// are made with a fake client).
func WithRoute53Client(api route53API) Option {
	return func(o *options) { o.route53 = api }
}

// ACMEChallengeFor renders the Traefik DNS-01 resolver block for the given
// provider name and credentials. Empty for providers without a DNS-01
// challenge (manual).
func ACMEChallengeFor(name string, cfg Config) string {
	switch name {
	case "cloudflare":
		return "dnschallenge.provider=cloudflare"
	case "route53":
		return "dnschallenge.provider=route53"
	default:
		return ""
	}
}

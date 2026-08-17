// Package config loads and validates platform configuration from the
// environment. Env names mirror the compose stack (see compose.yaml and
// .env.example).
package config

import (
	"errors"
	"fmt"
	"os"
	"time"
)

// Environment variable names. Single source of truth shared by compose,
// .env.example and tests.
const (
	EnvHTTPAddr        = "SELFU_HTTP_ADDR"
	EnvDatabaseURL     = "SELFU_DATABASE_URL"
	EnvSessionSecret   = "SELFU_SESSION_SECRET"
	EnvSessionTTL      = "SELFU_SESSION_TTL"
	EnvCookieSecure    = "SELFU_COOKIE_SECURE"
	EnvOIDCClientID    = "SELFU_OIDC_CLIENT_ID"
	EnvOIDCClientSecr  = "SELFU_OIDC_CLIENT_SECRET"
	EnvOIDCIssuer      = "SELFU_OIDC_ISSUER"
	EnvOIDCRedirectURL = "SELFU_OIDC_REDIRECT_URL"
	EnvAfterLoginPath  = "SELFU_AFTER_LOGIN_PATH"
	// EnvOIDCTLSInsecure disables TLS certificate verification for the
	// identity provider connection. Development only (self-signed local
	// certs); must be false in production.
	EnvOIDCTLSInsecure = "SELFU_OIDC_TLS_INSECURE"
	// EnvAuthentikURL and EnvAuthentikToken are the authentik admin API
	// base URL and service token used for identity provisioning (G2).
	EnvAuthentikURL   = "SELFU_AUTHENTIK_URL"
	EnvAuthentikToken = "SELFU_AUTHENTIK_TOKEN"
	// EnvCloudflareToken and EnvCloudflareZone optionally enable automatic
	// DNS provisioning via Cloudflare (G3); absent → Manual provider.
	EnvCloudflareToken = "SELFU_CLOUDFLARE_API_TOKEN"
	EnvCloudflareZone  = "SELFU_CLOUDFLARE_ZONE_ID"
	// EnvChasquidAgentURL and EnvChasquidAgentToken configure the
	// chasquid-agent sidecar (G4); absent → mail provisioning unavailable.
	EnvChasquidAgentURL   = "SELFU_CHASQUID_AGENT_URL"
	EnvChasquidAgentToken = "SELFU_CHASQUID_AGENT_TOKEN"
)

const (
	defaultHTTPAddr   = ":8080"
	defaultSessionTTL = 12 * time.Hour
)

// Config is the validated runtime configuration of the platform API.
type Config struct {
	HTTPAddr string
	DBURL    string

	SessionSecret []byte
	SessionTTL    time.Duration
	// CookieSecure sets the Secure attribute on platform session cookies.
	// Enable when served over HTTPS.
	CookieSecure bool

	// AfterLoginPath is where the browser is sent after the OIDC callback.
	AfterLoginPath string

	// Authentik is the authentik admin API configuration (identity
	// provisioning, spec §16). AuthentikTLSInsecure mirrors OIDC.TLSInsecure
	// for the admin connection.
	Authentik AuthentikConfig

	// Cloudflare optionally enables automatic DNS provisioning (G3).
	Cloudflare CloudflareConfig

	// Mail configures the chasquid controller (G4).
	Mail MailConfig

	OIDC OIDCConfig
}

// CloudflareConfig optionally configures the Cloudflare DNS provider.
type CloudflareConfig struct {
	APIToken string
	ZoneID   string
}

// MailConfig points at the chasquid-agent sidecar.
type MailConfig struct {
	AgentURL   string
	AgentToken string
}

// AuthentikConfig carries authentik admin API credentials.
type AuthentikConfig struct {
	BaseURL     string
	Token       string
	TLSInsecure bool
}

// OIDCConfig describes the platform's authentik OIDC client configuration.
type OIDCConfig struct {
	ClientID     string
	ClientSecret string
	// Issuer is authentik's OIDC issuer URL,
	// e.g. https://auth.example.com/application/o/platform/.
	Issuer      string
	RedirectURL string
	// TLSInsecure disables TLS verification for the issuer connection.
	// Development only; must be false in production.
	TLSInsecure bool
}

// Load reads and validates configuration from the environment.
func Load() (*Config, error) {
	var errs []error

	cfg := &Config{
		HTTPAddr:       getenv(EnvHTTPAddr, defaultHTTPAddr),
		SessionTTL:     defaultSessionTTL,
		AfterLoginPath: getenv(EnvAfterLoginPath, "/"),
	}

	if v := os.Getenv(EnvSessionTTL); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", EnvSessionTTL, err))
		} else {
			cfg.SessionTTL = d
		}
	}

	cfg.DBURL = required(EnvDatabaseURL, &errs)
	cfg.OIDC.ClientID = required(EnvOIDCClientID, &errs)
	cfg.OIDC.ClientSecret = required(EnvOIDCClientSecr, &errs)
	cfg.OIDC.Issuer = required(EnvOIDCIssuer, &errs)
	cfg.OIDC.RedirectURL = required(EnvOIDCRedirectURL, &errs)

	secret := os.Getenv(EnvSessionSecret)
	if secret == "" {
		errs = append(errs, fmt.Errorf("%s is required", EnvSessionSecret))
	} else if len(secret) < 32 {
		errs = append(errs, fmt.Errorf("%s must be at least 32 bytes", EnvSessionSecret))
	} else {
		cfg.SessionSecret = []byte(secret)
	}

	if v := os.Getenv(EnvCookieSecure); v != "" && v != "true" && v != "false" {
		errs = append(errs, fmt.Errorf("%s must be true or false", EnvCookieSecure))
	} else {
		cfg.CookieSecure = v == "true"
	}

	if v := os.Getenv(EnvOIDCTLSInsecure); v != "" && v != "true" && v != "false" {
		errs = append(errs, fmt.Errorf("%s must be true or false", EnvOIDCTLSInsecure))
	} else {
		cfg.OIDC.TLSInsecure = v == "true"
	}

	cfg.Authentik.BaseURL = required(EnvAuthentikURL, &errs)
	cfg.Authentik.Token = required(EnvAuthentikToken, &errs)
	cfg.Authentik.TLSInsecure = cfg.OIDC.TLSInsecure

	cfg.Cloudflare.APIToken = os.Getenv(EnvCloudflareToken)
	cfg.Cloudflare.ZoneID = os.Getenv(EnvCloudflareZone)

	cfg.Mail.AgentURL = os.Getenv(EnvChasquidAgentURL)
	cfg.Mail.AgentToken = os.Getenv(EnvChasquidAgentToken)

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return cfg, nil
}

func required(key string, errs *[]error) string {
	v := os.Getenv(key)
	if v == "" {
		*errs = append(*errs, fmt.Errorf("%s is required", key))
	}
	return v
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

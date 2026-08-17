package auth

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCConfig is the OIDC client configuration consumed by the provider.
type OIDCConfig struct {
	ClientID     string
	ClientSecret string
	Issuer       string
	RedirectURL  string
	// TLSInsecure disables TLS verification for the issuer connection.
	// Development only; must be false in production.
	TLSInsecure bool
}

// OIDCIdentity is the verified identity extracted from the ID token.
type OIDCIdentity struct {
	Subject     string
	Email       string
	DisplayName string
}

// OIDCProvider performs OIDC discovery and code exchange against
// authentik (spec §15). The platform never sees or stores passwords.
type OIDCProvider struct {
	cfg      OIDCConfig
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
}

// NewOIDCProvider performs OIDC discovery against cfg.Issuer and builds a
// token verifier for the platform's client.
func NewOIDCProvider(ctx context.Context, cfg OIDCConfig, logger *slog.Logger) (*OIDCProvider, error) {
	discoveryCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if cfg.TLSInsecure {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // dev-only, explicit opt-in
		client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
		discoveryCtx = oidc.ClientContext(discoveryCtx, client)
	}

	provider, err := oidc.NewProvider(discoveryCtx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery for %s: %w", cfg.Issuer, err)
	}

	p := &OIDCProvider{
		cfg: cfg,
		oauth: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  cfg.RedirectURL,
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		},
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
	}
	if logger != nil {
		logger.Info("oidc discovery complete", "issuer", cfg.Issuer)
	}
	return p, nil
}

// AuthCodeURL builds the authorization URL carrying the CSRF state and the
// anti-replay nonce.
func (p *OIDCProvider) AuthCodeURL(state, nonce string) string {
	return p.oauth.AuthCodeURL(state, oauth2.SetAuthURLParam("nonce", nonce))
}

// Exchange swaps the authorization code for tokens, verifies the ID token
// (signature, issuer, audience, nonce) and extracts the identity.
func (p *OIDCProvider) Exchange(ctx context.Context, code, expectedNonce string) (OIDCIdentity, error) {
	tok, err := p.oauth.Exchange(ctx, code)
	if err != nil {
		return OIDCIdentity{}, fmt.Errorf("oauth exchange: %w", err)
	}
	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok {
		return OIDCIdentity{}, errors.New("oauth exchange: no id_token in response")
	}

	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return OIDCIdentity{}, fmt.Errorf("id token verification: %w", err)
	}
	if idToken.Nonce != expectedNonce {
		return OIDCIdentity{}, errors.New("id token nonce mismatch")
	}

	var claims struct {
		Email             string `json:"email"`
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return OIDCIdentity{}, fmt.Errorf("id token claims: %w", err)
	}
	if idToken.Subject == "" {
		return OIDCIdentity{}, errors.New("id token missing subject")
	}
	if claims.Email == "" {
		return OIDCIdentity{}, errors.New("id token missing email claim")
	}

	displayName := claims.Name
	if displayName == "" {
		displayName = claims.PreferredUsername
	}
	if displayName == "" {
		displayName = localPart(claims.Email)
	}

	return OIDCIdentity{
		Subject:     idToken.Subject,
		Email:       claims.Email,
		DisplayName: displayName,
	}, nil
}

func localPart(email string) string {
	if i := strings.IndexByte(email, '@'); i > 0 {
		return email[:i]
	}
	return email
}

// RandomToken returns n bytes of cryptographically random data, base64url
// encoded, for OIDC state/nonce values.
func RandomToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("crypto/rand: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

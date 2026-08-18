// Package authentik is the platform's admin API client for authentik
// (spec §16, §79). It provisions and reconciles external users, groups and
// OIDC providers/applications against authentik. The platform coordinates
// authentik; it never duplicates its identity model.
package authentik

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Client talks to the authentik admin API (base URL + bootstrap/service
// token).
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// New builds the client; tlsInsecure relaxes certificate verification for
// self-signed dev instances (must be false in production).
func New(baseURL, token string, tlsInsecure bool) *Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if tlsInsecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // dev-only
	}
	return &Client{
		BaseURL: strings.TrimSuffix(baseURL, "/"),
		Token:   token,
		HTTP:    &http.Client{Transport: transport, Timeout: 15 * time.Second},
	}
}

// Do performs an authenticated JSON request and decodes the response into
// out (when non-nil).
func (c *Client) Do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	u := c.BaseURL + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("authentik %s %s: status %d: %s", method, path, resp.StatusCode, truncate(string(data), 400))
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, out)
}

// WaitReady polls the API until the token authenticates.
func (c *Client) WaitReady(ctx context.Context) error {
	var lastErr error
	for range 30 {
		lastErr = c.Do(ctx, http.MethodGet, "/api/v3/core/users/me/", nil, nil, nil)
		if lastErr == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
	return fmt.Errorf("authentik API not ready: %w", lastErr)
}

// EnsureUser creates (or reuses) the authentik user for a platform user and
// returns its external id (authentik user pks are integers) and whether it
// was newly created.
func (c *Client) EnsureUser(ctx context.Context, email, displayName string) (string, bool, error) {
	var existing struct {
		Results []struct {
			PK int `json:"pk"`
		} `json:"results"`
	}
	q := url.Values{"email": []string{email}}
	if err := c.Do(ctx, http.MethodGet, "/api/v3/core/users/", q, nil, &existing); err != nil {
		return "", false, err
	}
	if len(existing.Results) > 0 {
		return strconv.Itoa(existing.Results[0].PK), false, nil
	}

	var created struct {
		PK int `json:"pk"`
	}
	body := map[string]any{
		"username": email,
		"email":    email,
		"name":     firstNonEmpty(displayName, email),
	}
	if err := c.Do(ctx, http.MethodPost, "/api/v3/core/users/", nil, body, &created); err != nil {
		return "", false, err
	}
	return strconv.Itoa(created.PK), true, nil
}

// SetUserActive activates or disables the authentik user by external pk.
func (c *Client) SetUserActive(ctx context.Context, pk string, active bool) error {
	return c.Do(ctx, http.MethodPatch, "/api/v3/core/users/"+pk+"/", nil,
		map[string]any{"is_active": active}, nil)
}

// EnsureGroup creates (or reuses) the authentik group and returns its pk.
func (c *Client) EnsureGroup(ctx context.Context, name string) (string, error) {
	var existing struct {
		Results []struct {
			PK string `json:"pk"`
		} `json:"results"`
	}
	q := url.Values{"name": []string{name}}
	if err := c.Do(ctx, http.MethodGet, "/api/v3/core/groups/", q, nil, &existing); err != nil {
		return "", err
	}
	if len(existing.Results) > 0 {
		return existing.Results[0].PK, nil
	}
	var created struct {
		PK string `json:"pk"`
	}
	if err := c.Do(ctx, http.MethodPost, "/api/v3/core/groups/", nil,
		map[string]any{"name": name}, &created); err != nil {
		return "", err
	}
	return created.PK, nil
}

// flowPKByDesignation returns a flow pk by designation, preferring a slug
// prefix when given.
func (c *Client) flowPKByDesignation(ctx context.Context, designation, preferred string) (string, error) {
	var out struct {
		Results []struct {
			PK   string `json:"pk"`
			Slug string `json:"slug"`
		} `json:"results"`
	}
	q := url.Values{"designation": []string{designation}}
	if err := c.Do(ctx, http.MethodGet, "/api/v3/flows/instances/", q, nil, &out); err != nil {
		return "", err
	}
	if preferred != "" {
		for _, f := range out.Results {
			if strings.HasPrefix(f.Slug, preferred) {
				return f.PK, nil
			}
		}
	}
	if len(out.Results) > 0 {
		return out.Results[0].PK, nil
	}
	return "", fmt.Errorf("no authentik flow for designation %q", designation)
}

// signingKey returns an existing RSA signing key for OIDC ID tokens.
func (c *Client) signingKey(ctx context.Context) (string, error) {
	var out struct {
		Results []struct {
			PK   string `json:"pk"`
			Name string `json:"name"`
		} `json:"results"`
	}
	if err := c.Do(ctx, http.MethodGet, "/api/v3/crypto/certificatekeypairs/", nil, nil, &out); err != nil {
		return "", err
	}
	for _, k := range out.Results {
		if strings.HasPrefix(strings.ToLower(k.Name), "authentik") {
			return k.PK, nil
		}
	}
	if len(out.Results) > 0 {
		return out.Results[0].PK, nil
	}
	return "", errors.New("no authentik certificate keypair found")
}

// oauthScopeMappings returns the default OAuth scope-mapping pks for the
// given scopes (email, profile, openid). Without them authentik only
// supports the bare "openid" scope and rejects the profile/email scopes the
// platform requires.
func (c *Client) oauthScopeMappings(ctx context.Context, names ...string) ([]string, error) {
	var out struct {
		Results []struct {
			PK   string `json:"pk"`
			Name string `json:"name"`
		} `json:"results"`
	}
	q := url.Values{"page_size": []string{"200"}}
	if err := c.Do(ctx, http.MethodGet, "/api/v3/propertymappings/all/", q, nil, &out); err != nil {
		return nil, err
	}
	want := make(map[string]bool, len(names))
	for _, n := range names {
		want["authentik default OAuth Mapping: OpenID '"+n+"'"] = true
	}
	var pks []string
	for _, pm := range out.Results {
		if want[pm.Name] {
			pks = append(pks, pm.PK)
		}
	}
	return pks, nil
}

// EnsureOIDCProvider creates or reuses the confidential OAuth2/OIDC provider
// for the platform client and returns its integer pk.
func (c *Client) EnsureOIDCProvider(ctx context.Context, clientID, clientSecret, redirectURL, slug string) (int, error) {
	var existing struct {
		Results []struct {
			PK int `json:"pk"`
		} `json:"results"`
	}
	q := url.Values{"client_id": []string{clientID}}
	if err := c.Do(ctx, http.MethodGet, "/api/v3/providers/oauth2/", q, nil, &existing); err != nil {
		return 0, err
	}
	if len(existing.Results) > 0 {
		return existing.Results[0].PK, nil
	}

	flowPK, err := c.flowPKByDesignation(ctx, "authorization", "default-provider-authorization-explicit-consent")
	if err != nil {
		return 0, err
	}
	invalidationPK, err := c.flowPKByDesignation(ctx, "invalidation", "default-provider-invalidation-flow")
	if err != nil {
		return 0, err
	}
	keyPK, err := c.signingKey(ctx)
	if err != nil {
		return 0, err
	}
	scopes, err := c.oauthScopeMappings(ctx, "email", "profile", "openid")
	if err != nil {
		return 0, err
	}

	body := map[string]any{
		"name":               slug,
		"authorization_flow": flowPK,
		"invalidation_flow":  invalidationPK,
		"client_type":        "confidential",
		"client_id":          clientID,
		"client_secret":      clientSecret,
		"redirect_uris":      []map[string]any{{"url": redirectURL, "matching_mode": "strict"}},
		"signing_key":        keyPK,
		"grant_types":        []string{"authorization_code"},
		"property_mappings":  scopes,
	}
	var created struct {
		PK int `json:"pk"`
	}
	if err := c.Do(ctx, http.MethodPost, "/api/v3/providers/oauth2/", nil, body, &created); err != nil {
		return 0, err
	}
	return created.PK, nil
}

// AppOIDC is the result of provisioning an application's OIDC provider.
type AppOIDC struct {
	ProviderPK    int
	ApplicationPK string
	ClientID      string
	ClientSecret  string
}

// EnsureAppOIDC provisions (idempotently) a confidential OIDC provider and
// application for a third-party app (spec §82). Returns freshly generated
// client credentials; the app must be configured with them.
func (c *Client) EnsureAppOIDC(ctx context.Context, name, slug, redirectURI string) (AppOIDC, error) {
	clientID := "app-" + slug
	clientSecret := randHex(32)

	var existing struct {
		Results []struct {
			PK int `json:"pk"`
		} `json:"results"`
	}
	q := url.Values{"client_id": []string{clientID}}
	if err := c.Do(ctx, http.MethodGet, "/api/v3/providers/oauth2/", q, nil, &existing); err != nil {
		return AppOIDC{}, err
	}
	providerPK := 0
	if len(existing.Results) > 0 {
		providerPK = existing.Results[0].PK
	}
	if providerPK == 0 {
		flowPK, err := c.flowPKByDesignation(ctx, "authorization", "default-provider-authorization-explicit-consent")
		if err != nil {
			return AppOIDC{}, err
		}
		invalidationPK, err := c.flowPKByDesignation(ctx, "invalidation", "default-provider-invalidation-flow")
		if err != nil {
			return AppOIDC{}, err
		}
		keyPK, err := c.signingKey(ctx)
		if err != nil {
			return AppOIDC{}, err
		}
		scopes, err := c.oauthScopeMappings(ctx, "email", "profile", "openid")
		if err != nil {
			return AppOIDC{}, err
		}
		var created struct {
			PK int `json:"pk"`
		}
		if err := c.Do(ctx, http.MethodPost, "/api/v3/providers/oauth2/", nil, map[string]any{
			"name":               name,
			"authorization_flow": flowPK,
			"invalidation_flow":  invalidationPK,
			"client_type":        "confidential",
			"client_id":          clientID,
			"client_secret":      clientSecret,
			"redirect_uris":      []map[string]any{{"url": redirectURI, "matching_mode": "regex"}},
			"signing_key":        keyPK,
			"grant_types":        []string{"authorization_code"},
			"property_mappings":  scopes,
		}, &created); err != nil {
			return AppOIDC{}, err
		}
		providerPK = created.PK
	}

	// authentik's application list ignores slug/provider query filters, so
	// dedup by scanning the full result set client-side.
	var all struct {
		Results []struct {
			PK       string `json:"pk"`
			Slug     string `json:"slug"`
			Provider *int   `json:"provider"`
		} `json:"results"`
	}
	if err := c.Do(ctx, http.MethodGet, "/api/v3/core/applications/", url.Values{"page_size": []string{"200"}}, nil, &all); err != nil {
		return AppOIDC{}, err
	}
	appPK := ""
	for _, a := range all.Results {
		if a.Slug == slug && a.Provider != nil && *a.Provider == providerPK {
			appPK = a.PK
			break
		}
	}
	if appPK == "" {
		var created struct {
			PK string `json:"pk"`
		}
		if err := c.Do(ctx, http.MethodPost, "/api/v3/core/applications/", nil,
			map[string]any{"name": name, "slug": slug, "provider": providerPK}, &created); err != nil {
			return AppOIDC{}, err
		}
		appPK = created.PK
	}
	return AppOIDC{ProviderPK: providerPK, ApplicationPK: appPK, ClientID: clientID, ClientSecret: clientSecret}, nil
}

// EnsureForwardAuth provisions an authentik forward-auth (proxy) provider
// and application for a legacy app (spec §83).
func (c *Client) EnsureForwardAuth(ctx context.Context, name, slug, externalHost string) (AppOIDC, error) {
	// Bit relative to filesystem dirs. Dedup by scanning provider list
	// (authentik ignores name filters on list).
	var all struct {
		Results []struct {
			PK   int    `json:"pk"`
			Name string `json:"name"`
		} `json:"results"`
	}
	if err := c.Do(ctx, http.MethodGet, "/api/v3/providers/proxy/", url.Values{"page_size": []string{"200"}}, nil, &all); err != nil {
		return AppOIDC{}, err
	}
	providerPK := 0
	for _, p := range all.Results {
		if p.Name == name {
			providerPK = p.PK
			break
		}
	}
	if providerPK == 0 {
		flowPK, err := c.flowPKByDesignation(ctx, "authorization", "default-provider-authorization-explicit-consent")
		if err != nil {
			return AppOIDC{}, err
		}
		invalidationPK, err := c.flowPKByDesignation(ctx, "invalidation", "default-provider-invalidation-flow")
		if err != nil {
			return AppOIDC{}, err
		}
		var created struct {
			PK int `json:"pk"`
		}
		if err := c.Do(ctx, http.MethodPost, "/api/v3/providers/proxy/", nil, map[string]any{
			"name":               name,
			"authorization_flow": flowPK,
			"invalidation_flow":  invalidationPK,
			"external_host":      externalHost,
			"mode":               "forward_single",
			"cookie_secure":      false,
		}, &created); err != nil {
			return AppOIDC{}, err
		}
		providerPK = created.PK
	}

	var apps struct {
		Results []struct {
			PK       string `json:"pk"`
			Slug     string `json:"slug"`
			Provider *int   `json:"provider"`
		} `json:"results"`
	}
	if err := c.Do(ctx, http.MethodGet, "/api/v3/core/applications/", url.Values{"page_size": []string{"200"}}, nil, &apps); err != nil {
		return AppOIDC{}, err
	}
	appPK := ""
	for _, a := range apps.Results {
		if a.Slug == slug && a.Provider != nil && *a.Provider == providerPK {
			appPK = a.PK
			break
		}
	}
	if appPK == "" {
		var created struct {
			PK string `json:"pk"`
		}
		if err := c.Do(ctx, http.MethodPost, "/api/v3/core/applications/", nil,
			map[string]any{"name": name, "slug": slug, "provider": providerPK}, &created); err != nil {
			return AppOIDC{}, err
		}
		appPK = created.PK
	}
	return AppOIDC{ProviderPK: providerPK, ApplicationPK: appPK}, nil
}

// EnsureApplication attaches a provider to the application with the slug.
func (c *Client) EnsureApplication(ctx context.Context, slug string, providerPK int) error {
	var existing struct {
		Results []struct {
			PK string `json:"pk"`
		} `json:"results"`
	}
	q := url.Values{"slug": []string{slug}}
	if err := c.Do(ctx, http.MethodGet, "/api/v3/core/applications/", q, nil, &existing); err != nil {
		return err
	}
	if len(existing.Results) > 0 {
		return nil
	}
	return c.Do(ctx, http.MethodPost, "/api/v3/core/applications/", nil,
		map[string]any{"name": "Selfu Platform", "slug": slug, "provider": providerPK}, nil)
}

// randHex returns n random bytes hex-encoded.
func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

// firstNonEmpty returns a if non-empty else b.
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

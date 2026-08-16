// Command authentik-bootstrap provisions the platform's OIDC provider and
// application in a fresh authentik instance via its admin API. It is
// idempotent and safe to re-run. Phase 2 (goal G2) replaces this one-shot
// with the platform-owned identity provisioning client (spec §16, §79).
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "authentik-bootstrap:", err)
		os.Exit(1)
	}
	fmt.Println("authentik-bootstrap: OIDC provider and application ensured")
}

func run(ctx context.Context) error {
	base := strings.TrimSuffix(os.Getenv("AUTHENTIK_BASE_URL"), "/")
	token := os.Getenv("AUTHENTIK_BOOTSTRAP_TOKEN")
	clientID := os.Getenv("SELFU_OIDC_CLIENT_ID")
	clientSecret := os.Getenv("SELFU_OIDC_CLIENT_SECRET")
	redirectURL := os.Getenv("SELFU_OIDC_REDIRECT_URL")
	slug := os.Getenv("SELFU_OIDC_SLUG")
	if slug == "" {
		slug = "selfu"
	}

	for _, v := range []struct{ name, val string }{
		{"AUTHENTIK_BASE_URL", base},
		{"AUTHENTIK_BOOTSTRAP_TOKEN", token},
		{"SELFU_OIDC_CLIENT_ID", clientID},
		{"SELFU_OIDC_CLIENT_SECRET", clientSecret},
		{"SELFU_OIDC_REDIRECT_URL", redirectURL},
	} {
		if v.val == "" {
			return fmt.Errorf("%s is required", v.name)
		}
	}

	a := &api{
		base:   base,
		token:  token,
		client: &http.Client{Timeout: 15 * time.Second},
	}

	if err := a.waitReady(ctx); err != nil {
		return err
	}

	providerPK, err := a.ensureOIDCProvider(ctx, clientID, clientSecret, redirectURL, slug)
	if err != nil {
		return err
	}
	return a.ensureApplication(ctx, slug, providerPK)
}

// api is a minimal authentik admin API client.
type api struct {
	base   string
	token  string
	client *http.Client
}

// waitReady polls the API until the bootstrap token authenticates.
func (a *api) waitReady(ctx context.Context) error {
	var lastErr error
	for range 30 {
		_, lastErr = a.do(ctx, http.MethodGet, "/api/v3/core/users/me", nil, nil)
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

type flow struct {
	PK int `json:"pk"`
}

func (a *api) authorizationFlow(ctx context.Context) (int, error) {
	var out struct {
		Results []flow `json:"results"`
	}
	q := url.Values{"designation": []string{"authorization"}}
	if err := a.doInto(ctx, http.MethodGet, "/api/v3/flows/", q, nil, &out); err != nil {
		return 0, err
	}
	if len(out.Results) == 0 {
		return 0, errors.New("no authorization flow found; did authentik bootstrap its default flows?")
	}
	return out.Results[0].PK, nil
}

type keyPair struct {
	PK   int    `json:"pk"`
	Name string `json:"name"`
}

// signingKey returns an existing RSA signing key for OIDC ID tokens.
func (p *api) signingKey(ctx context.Context) (int, error) {
	var out struct {
		Results []keyPair `json:"results"`
	}
	if err := p.doInto(ctx, http.MethodGet, "/api/v3/crypto/certificatekeypairs/", nil, nil, &out); err != nil {
		return 0, err
	}
	for _, k := range out.Results {
		if strings.HasPrefix(strings.ToLower(k.Name), "authentik") {
			return k.PK, nil
		}
	}
	if len(out.Results) > 0 {
		return out.Results[0].PK, nil
	}
	return 0, errors.New("no certificate keypair found")
}

// ensureOIDCProvider creates or reuses the confidential OIDC provider for
// the platform client and returns its primary key.
func (a *api) ensureOIDCProvider(ctx context.Context, clientID, clientSecret, redirectURL, slug string) (int, error) {
	var existing struct {
		Results []struct {
			PK int `json:"pk"`
		} `json:"results"`
	}
	q := url.Values{"client_id": []string{clientID}}
	if err := a.doInto(ctx, http.MethodGet, "/api/v3/providers/oidc/", q, nil, &existing); err != nil {
		return 0, err
	}
	if len(existing.Results) > 0 {
		return existing.Results[0].PK, nil
	}

	flowPK, err := a.authorizationFlow(ctx)
	if err != nil {
		return 0, err
	}
	keyPK, err := a.signingKey(ctx)
	if err != nil {
		return 0, err
	}

	body := map[string]any{
		"name":               slug,
		"authorization_flow": flowPK,
		"client_type":        "confidential",
		"client_id":          clientID,
		"client_secret":      clientSecret,
		"redirect_uris":      []string{redirectURL},
		"signing_key":        keyPK,
	}
	var created struct {
		PK int `json:"pk"`
	}
	if err := a.doInto(ctx, http.MethodPost, "/api/v3/providers/oidc/", nil, body, &created); err != nil {
		return 0, err
	}
	return created.PK, nil
}

// ensureApplication attaches the provider to the application with the
// given slug.
func (a *api) ensureApplication(ctx context.Context, slug string, providerPK int) error {
	var existing struct {
		Results []struct {
			PK int `json:"pk"`
		} `json:"results"`
	}
	q := url.Values{"slug": []string{slug}}
	if err := a.doInto(ctx, http.MethodGet, "/api/v3/core/applications/", q, nil, &existing); err != nil {
		return err
	}
	if len(existing.Results) > 0 {
		return nil
	}

	body := map[string]any{
		"name":     "Selfu Platform",
		"slug":     slug,
		"provider": providerPK,
	}
	return a.doInto(ctx, http.MethodPost, "/api/v3/core/applications/", nil, body, nil)
}

// do performs a request and returns the raw response body.
func (a *api) do(ctx context.Context, method, path string, q url.Values, body any) ([]byte, error) {
	u := a.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}

	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("authentik %s %s: status %d: %s", method, path, resp.StatusCode, truncate(string(data), 300))
	}
	return data, nil
}

func (a *api) doInto(ctx context.Context, method, path string, q url.Values, body any, out any) error {
	data, err := a.do(ctx, method, path, q, body)
	if err != nil {
		return err
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, out)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

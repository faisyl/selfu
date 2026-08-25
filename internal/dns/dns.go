// Package dns provides the DNS provider abstraction (spec §88) and TXT
// lookup used for domain ownership verification (spec §11).
package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrManual is returned by providers that do not auto-provision records; the
// user must add them, and verification still happens by public lookup.
var ErrManual = errors.New("dns: manual provider does not auto-set records")

// Provider provisions DNS records for platform domains.
type Provider interface {
	// Name is the provider identifier ("manual", "cloudflare").
	Name() string
	// SetTXT ensures a TXT record holds value at fqdn.
	SetTXT(ctx context.Context, fqdn, value string) error
	// RemoveTXT deletes a TXT record with the given value.
	RemoveTXT(ctx context.Context, fqdn, value string) error
	// SetAddr ensures an A record points fqdn at ip. The external access
	// surface uses this to publish platform hostnames (spec §59).
	SetAddr(ctx context.Context, fqdn, ip string) error
	// RemoveAddr removes the A record for fqdn.
	RemoveAddr(ctx context.Context, fqdn, ip string) error
}

// ManualProvider emits instructions; it never auto-provisions records.
type ManualProvider struct{}

// Name matches the "manual" provider identifier.
func (ManualProvider) Name() string { return "manual" }

// SetTXT reports that manual provisioning is required.
func (ManualProvider) SetTXT(context.Context, string, string) error { return ErrManual }

// RemoveTXT reports that manual removal is required.
func (ManualProvider) RemoveTXT(context.Context, string, string) error { return ErrManual }

// SetAddr reports that manual provisioning is required.
func (ManualProvider) SetAddr(context.Context, string, string) error { return ErrManual }

// RemoveAddr reports that manual removal is required.
func (ManualProvider) RemoveAddr(context.Context, string, string) error { return ErrManual }

// TXTLookup returns the TXT records for a name.
type TXTLookup func(ctx context.Context, fqdn string) ([]string, error)

// DefaultTXTLookup uses the system resolver.
var DefaultTXTLookup TXTLookup = func(ctx context.Context, fqdn string) ([]string, error) {
	return net.DefaultResolver.LookupTXT(ctx, fqdn)
}

// VerifyRecordName is the DNS name for ownership verification (spec §11).
func VerifyRecordName(domain string) string {
	return "_platform-verification." + strings.TrimSuffix(domain, ".")
}

// TokenTXTValue renders the expected TXT payload for a verification token.
func TokenTXTValue(token string) string {
	return "platform=" + token
}

// CloudflareConfig holds credentials for the Cloudflare provider.
type CloudflareConfig struct {
	APIToken string
	ZoneID   string
	// BaseURL overridable for testing.
	BaseURL string
}

// CloudflareProvider provisions TXT records via the Cloudflare API v4.
type CloudflareProvider struct {
	cfg  CloudflareConfig
	http *http.Client
}

// NewCloudflare builds the Cloudflare provider.
func NewCloudflare(cfg CloudflareConfig) *CloudflareProvider {
	base := cfg.BaseURL
	if base == "" {
		base = "https://api.cloudflare.com/client/v4"
	}
	return &CloudflareProvider{cfg: cfg, http: &http.Client{Timeout: 15 * time.Second}}
}

// Name matches the "cloudflare" provider identifier.
func (c *CloudflareProvider) Name() string { return "cloudflare" }

// ZoneExists verifies the configured zone is reachable with the given
// credentials. Used to validate provider configuration before onboarding.
func (c *CloudflareProvider) ZoneExists(ctx context.Context) error {
	var resp struct {
		Success bool                       `json:"success"`
		Errors  []struct{ Message string } `json:"errors"`
		Result  struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"result"`
	}
	if err := c.do(ctx, http.MethodGet, "/zones/"+c.cfg.ZoneID, nil, &resp); err != nil {
		return err
	}
	if !resp.Success {
		return fmt.Errorf("cloudflare zone check: %v", resp.Errors)
	}
	if resp.Result.ID == "" {
		return fmt.Errorf("cloudflare zone %s not found", c.cfg.ZoneID)
	}
	return nil
}

// ZoneIDByDomain resolves the Cloudflare zone id for a domain (spec §88:
// onboarding needs only a domain + API token). Returns a descriptive error
// when the account does not host the domain.
func (c *CloudflareProvider) ZoneIDByDomain(ctx context.Context, domain string) (string, error) {
	q := "name=" + url.QueryEscape(strings.TrimSuffix(domain, "."))
	var resp struct {
		Success bool                       `json:"success"`
		Errors  []struct{ Message string } `json:"errors"`
		Result  []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"result"`
	}
	if err := c.do(ctx, http.MethodGet, "/zones?"+q, nil, &resp); err != nil {
		return "", err
	}
	if !resp.Success {
		return "", fmt.Errorf("cloudflare zone lookup: %v", resp.Errors)
	}
	for _, z := range resp.Result {
		if strings.EqualFold(z.Name, strings.TrimSuffix(domain, ".")) {
			return z.ID, nil
		}
	}
	return "", fmt.Errorf("no cloudflare zone found for %s (is the domain on this account?)", domain)
}

// SetTXT creates the TXT record (idempotent: records may carry multiple
// strings, so an existing matching record is left alone).
func (c *CloudflareProvider) SetTXT(ctx context.Context, fqdn, value string) error {
	if err := c.ensureRecord(ctx, fqdn, value); err != nil {
		return err
	}
	return nil
}

// RemoveTXT removes a TXT record whose content equals value.
func (c *CloudflareProvider) RemoveTXT(ctx context.Context, fqdn, value string) error {
	type item struct {
		ID      string `json:"id"`
		Content string `json:"content"`
	}
	q := "type=TXT&name=" + fqdn
	var resp struct {
		Success bool                       `json:"success"`
		Errors  []struct{ Message string } `json:"errors"`
		Result  []item                     `json:"result"`
	}
	if err := c.do(ctx, http.MethodGet, "/zones/"+c.cfg.ZoneID+"/dns_records?"+q, nil, &resp); err != nil {
		return err
	}
	if !resp.Success {
		return fmt.Errorf("cloudflare list: %v", resp.Errors)
	}
	for _, r := range resp.Result {
		if r.Content == value {
			return c.do(ctx, http.MethodDelete, "/zones/"+c.cfg.ZoneID+"/dns_records/"+r.ID, nil, nil)
		}
	}
	return nil
}

// SetAddr ensures an A record points fqdn at ip (idempotent).
func (c *CloudflareProvider) SetAddr(ctx context.Context, fqdn, ip string) error {
	body := map[string]any{
		"type":    "A",
		"name":    fqdn,
		"content": ip,
		"ttl":     120,
	}
	var resp struct {
		Success bool                       `json:"success"`
		Errors  []struct{ Message string } `json:"errors"`
		Result  []struct {
			Content string `json:"content"`
		} `json:"result"`
	}
	if err := c.do(ctx, http.MethodGet, "/zones/"+c.cfg.ZoneID+"/dns_records?type=A&name="+fqdn, nil, &resp); err != nil {
		return err
	}
	if resp.Success {
		for _, r := range resp.Result {
			if r.Content == ip {
				return nil // already present
			}
		}
	}
	return c.do(ctx, http.MethodPost, "/zones/"+c.cfg.ZoneID+"/dns_records", body, nil)
}

// RemoveAddr removes the A record for fqdn.
func (c *CloudflareProvider) RemoveAddr(ctx context.Context, fqdn, ip string) error {
	type item struct {
		ID      string `json:"id"`
		Content string `json:"content"`
	}
	q := "type=A&name=" + fqdn
	var resp struct {
		Success bool                       `json:"success"`
		Errors  []struct{ Message string } `json:"errors"`
		Result  []item                     `json:"result"`
	}
	if err := c.do(ctx, http.MethodGet, "/zones/"+c.cfg.ZoneID+"/dns_records?"+q, nil, &resp); err != nil {
		return err
	}
	if !resp.Success {
		return fmt.Errorf("cloudflare list: %v", resp.Errors)
	}
	for _, r := range resp.Result {
		if r.Content == ip {
			return c.do(ctx, http.MethodDelete, "/zones/"+c.cfg.ZoneID+"/dns_records/"+r.ID, nil, nil)
		}
	}
	return nil
}

func (c *CloudflareProvider) ensureRecord(ctx context.Context, fqdn, value string) error {
	body := map[string]any{
		"type":    "TXT",
		"name":    fqdn,
		"content": value,
		"ttl":     120,
	}
	var resp struct {
		Success bool                       `json:"success"`
		Errors  []struct{ Message string } `json:"errors"`
		Result  []struct {
			Content string `json:"content"`
		} `json:"result"`
	}
	if err := c.do(ctx, http.MethodGet, "/zones/"+c.cfg.ZoneID+"/dns_records?type=TXT&name="+fqdn, nil, &resp); err != nil {
		return err
	}
	if resp.Success {
		for _, r := range resp.Result {
			if r.Content == value {
				return nil // already present
			}
		}
	}
	return c.do(ctx, http.MethodPost, "/zones/"+c.cfg.ZoneID+"/dns_records", body, nil)
}

func (c *CloudflareProvider) do(ctx context.Context, method, path string, body any, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	url := c.cfg.BaseURL + path
	if url == "" || !strings.HasPrefix(url, "http") {
		url = "https://api.cloudflare.com/client/v4" + path
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.APIToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("cloudflare %s %s: status %d", method, path, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

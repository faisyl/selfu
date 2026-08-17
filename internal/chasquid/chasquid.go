// Package chasquid integrates the platform with the chasquid MTA (spec §23,
// §58–§59). The Maya provider talks to the chasquid-agent sidecar, which is
// the only component that invokes chasquid-util; the platform never touches
// chasquid file formats directly (§33).
package chasquid

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Secret is an SMTP credential secret. It redacts itself from logs and is
// never JSON-marshaled by the platform (spec §62, §68).
type Secret string

// String redacts the secret from any log output.
func (s Secret) String() string { return "***" }

// ChasquidStatus reports the MTA's health (§66).
type ChasquidStatus struct {
	Healthy bool
	Detail  string
}

// ChasquidController is the narrow interface the provider needs (spec §59);
// it permits later replacement with a remote chasquid / API wrapper / sidecar
// without changing the platform model.
type ChasquidController interface {
	AddUser(ctx context.Context, address string, password Secret) error
	RemoveUser(ctx context.Context, address string) error
	ChangePassword(ctx context.Context, address string, password Secret) error
	EnsureDomain(ctx context.Context, domain string) error
	RemoveDomain(ctx context.Context, domain string) error
	EnsureAlias(ctx context.Context, domain, localPart string, destinations []string) error
	RemoveAlias(ctx context.Context, domain, localPart string) error
	Reload(ctx context.Context) error
	// Restart fully restarts the MTA; required when new domains are
	// provisioned (spec §91).
	Restart(ctx context.Context) error
	Status(ctx context.Context) (ChasquidStatus, error)
}

// ErrUnavailable is returned when no controller is configured.
var ErrUnavailable = errors.New("chasquid: controller unavailable")

// AgentClient is a ChasquidController backed by the chasquid-agent sidecar.
type AgentClient struct {
	base  string
	token string
	http  *http.Client
}

// NewAgentClient builds the controller for the sidecar at base.
func NewAgentClient(base, token string) *AgentClient {
	return &AgentClient{
		base:  strings.TrimSuffix(base, "/"),
		token: token,
		http:  &http.Client{Timeout: 20 * time.Second},
	}
}

func (c *AgentClient) do(ctx context.Context, method, path string, body any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = strings.NewReader(string(b))
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("X-Agent-Token", c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("chasquid-agent %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("chasquid-agent %s %s: status %d: %s", method, path, resp.StatusCode, truncate(string(data), 250))
	}
	return nil
}

// AddUser provisions a chasquid user with the given secret.
func (c *AgentClient) AddUser(ctx context.Context, address string, password Secret) error {
	return c.do(ctx, http.MethodPost, "/api/v1/user", map[string]string{
		"address": address, "password": string(password),
	})
}

// RemoveUser removes a chasquid user.
func (c *AgentClient) RemoveUser(ctx context.Context, address string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/user", map[string]string{"address": address})
}

// ChangePassword rotates a chasquid user's secret.
func (c *AgentClient) ChangePassword(ctx context.Context, address string, password Secret) error {
	return c.do(ctx, http.MethodPost, "/api/v1/user/password", map[string]string{
		"address": address, "password": string(password),
	})
}

// EnsureDomain creates the domain directory.
func (c *AgentClient) EnsureDomain(ctx context.Context, domain string) error {
	return c.do(ctx, http.MethodPost, "/api/v1/domain", map[string]string{"domain": domain})
}

// RemoveDomain removes the domain directory (explicit removal only).
func (c *AgentClient) RemoveDomain(ctx context.Context, domain string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/domain", map[string]string{"domain": domain})
}

// EnsureAlias writes the alias line for localPart (spec §28, §37).
func (c *AgentClient) EnsureAlias(ctx context.Context, domain, localPart string, destinations []string) error {
	return c.do(ctx, http.MethodPost, "/api/v1/alias", map[string]any{
		"domain": domain, "local": localPart, "destinations": destinations,
	})
}

// RemoveAlias deletes the alias line for localPart.
func (c *AgentClient) RemoveAlias(ctx context.Context, domain, localPart string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/alias", map[string]string{
		"domain": domain, "local": localPart,
	})
}

// Reload asks chasquid to reload its configuration.
func (c *AgentClient) Reload(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/api/v1/reload", nil)
}

// Restart fully restarts the chasquid daemon (new-domain registration).
func (c *AgentClient) Restart(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/api/v1/restart", nil)
}

// Status checks the agent's health probe (config validity + daemon alive).
func (c *AgentClient) Status(ctx context.Context) (ChasquidStatus, error) {
	err := c.do(ctx, http.MethodGet, "/healthz", nil)
	if err != nil {
		return ChasquidStatus{Healthy: false, Detail: err.Error()}, nil
	}
	return ChasquidStatus{Healthy: true}, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

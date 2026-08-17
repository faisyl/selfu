// Command authentik-bootstrap provisions the platform's OIDC provider and
// application in a fresh authentik instance (idempotent). It is a thin
// wrapper over internal/authentik; user/group provisioning for the platform
// API uses the same client.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"selfu/internal/authentik"
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
	base := os.Getenv("AUTHENTIK_BASE_URL")
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

	c := authentik.New(base, token, os.Getenv("AUTHENTIK_TLS_INSECURE") == "true")
	if err := c.WaitReady(ctx); err != nil {
		return err
	}
	providerPK, err := c.EnsureOIDCProvider(ctx, clientID, clientSecret, redirectURL, slug)
	if err != nil {
		return err
	}
	return c.EnsureApplication(ctx, slug, providerPK)
}

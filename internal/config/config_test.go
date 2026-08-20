package config

import (
	"strings"
	"testing"
	"time"
)

func setAll(t *testing.T) {
	t.Helper()
	t.Setenv(EnvDatabaseURL, "postgres://u:p@localhost:5432/selfu")
	t.Setenv(EnvSessionSecret, strings.Repeat("s", 32))
	t.Setenv(EnvOIDCClientID, "client")
	t.Setenv(EnvOIDCClientSecr, "secret")
	t.Setenv(EnvOIDCIssuer, "https://auth.example.com/application/o/platform")
	t.Setenv(EnvOIDCRedirectURL, "http://localhost:8080/api/v1/auth/callback")
	t.Setenv(EnvAuthentikURL, "https://auth.example.com")
	t.Setenv(EnvAuthentikToken, "s3cr3t-token")
	// Hermetic: clear optional vars so ambient environment cannot leak in.
	t.Setenv(EnvCookieSecure, "")
	t.Setenv(EnvOIDCTLSInsecure, "")
}

func TestLoadDefaults(t *testing.T) {
	setAll(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.HTTPAddr != ":8080" {
		t.Errorf("HTTPAddr = %q, want :8080", cfg.HTTPAddr)
	}
	if cfg.SessionTTL != 12*time.Hour {
		t.Errorf("SessionTTL = %v, want 12h", cfg.SessionTTL)
	}
	if cfg.CookieSecure {
		t.Error("CookieSecure = true, want false by default")
	}
}

func TestLoadRejectsMissingRequired(t *testing.T) {
	setAll(t)
	t.Setenv(EnvDatabaseURL, "")
	_, err := Load()
	if err == nil {
		t.Fatal("Load() error = nil, want missing-var error")
	}
	if !strings.Contains(err.Error(), EnvDatabaseURL) {
		t.Errorf("error %q does not mention %s", err, EnvDatabaseURL)
	}
}

func TestLoadRejectsShortSecret(t *testing.T) {
	setAll(t)
	t.Setenv(EnvSessionSecret, "short")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), EnvSessionSecret) {
		t.Fatalf("Load() error = %v, want short-secret error", err)
	}
}

func TestLoadRejectsBadTTL(t *testing.T) {
	setAll(t)
	t.Setenv(EnvSessionTTL, "not-a-duration")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), EnvSessionTTL) {
		t.Fatalf("Load() error = %v, want TTL parse error", err)
	}
}

func TestLoadCookieSecure(t *testing.T) {
	setAll(t)
	t.Setenv(EnvCookieSecure, "true")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.CookieSecure {
		t.Error("CookieSecure = false, want true")
	}
	t.Setenv(EnvCookieSecure, "maybe")
	if _, err := Load(); err == nil {
		t.Error("Load() with CookieSecure=maybe: want error")
	}
}

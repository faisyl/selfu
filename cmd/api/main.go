// Command api runs the platform HTTP API.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"selfu/internal/access"
	"selfu/internal/auth"
	"selfu/internal/authentik"
	"selfu/internal/chasquid"
	"selfu/internal/config"
	"selfu/internal/dns"
	"selfu/internal/httpapi"
	"selfu/internal/store"
	"selfu/internal/version"
)

// The pg store satisfies every handler seam, including invites.
var _ httpapi.InviteStore = (*store.Store)(nil)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("api fatal", "err", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(ctx, cfg.DBURL)
	if err != nil {
		return err
	}
	defer st.Close()

	sessions, err := auth.NewSessionStore(auth.SessionStoreOptions{
		Name:   "selfu_session",
		Secret: cfg.SessionSecret,
		TTL:    cfg.SessionTTL,
		Secure: cfg.CookieSecure,
	})
	if err != nil {
		return err
	}

	prov, err := auth.NewOIDCProvider(ctx, auth.OIDCConfig{
		ClientID:     cfg.OIDC.ClientID,
		ClientSecret: cfg.OIDC.ClientSecret,
		Issuer:       cfg.OIDC.Issuer,
		RedirectURL:  cfg.OIDC.RedirectURL,
		TLSInsecure:  cfg.OIDC.TLSInsecure,
	}, logger)
	if err != nil {
		return err
	}

	// Identity admin client for user/group provisioning (G2).
	ak := authentik.New(cfg.Authentik.BaseURL, cfg.Authentik.Token, cfg.Authentik.TLSInsecure)

	// External access provider: env-configured Cloudflare credentials win;
	// otherwise fall back to the provider stored by the wizard (G8/G9).
	accessProvider, err := loadAccessProvider(ctx, st, cfg)
	if err != nil {
		return err
	}
	dnsProvider := accessProvider.DNS()

	// Chasquid controller (G4); nil when the agent is not configured.
	var chasquidCtrl chasquid.ChasquidController
	if cfg.Mail.AgentURL != "" && cfg.Mail.AgentToken != "" {
		chasquidCtrl = chasquid.NewAgentClient(cfg.Mail.AgentURL, cfg.Mail.AgentToken)
	}

	apiHandler := httpapi.NewHandler(httpapi.Deps{
		Logger:            logger,
		Sessions:          sessions,
		OIDC:              prov,
		Users:             st,
		Audit:             st,
		OIDCConfig:        cfg.OIDC,
		AfterLoginPath:    cfg.AfterLoginPath,
		IdentityStore:     st,
		Identity:          ak,
		ProviderName:      cfg.OIDC.Issuer,
		Invites:           st,
		PasswordSetter:    ak,
		DomainStore:       st,
		DNSProvider:       dnsProvider,
		TXTLookup:         txtLookup(cfg),
		MailStore:         st,
		Recon:             st,
		Chasquid:          chasquidCtrl,
		MailProvision:     chasquidCtrl,
		Apps:              st,
		Setup:             st,
		AccessProvider:    accessProvider,
		LocalDomain:       cfg.LocalDomain,
		PublicIP:          cfg.PublicIP,
		BootstrapEmail:    cfg.BootstrapEmail,
		BootstrapPassword: cfg.BootstrapPassword,
		EncryptionKey:     cfg.SessionSecret,
	})

	// Background auto-verify loop: completes onboarding once the primary
	// domain's TXT record propagates, even with no browser open.
	pollInterval := 15 * time.Second
	if v := os.Getenv("SELFU_VERIFY_POLL_INTERVAL"); v != "" {
		if secs, perr := strconv.Atoi(v); perr == nil && secs > 0 {
			pollInterval = time.Duration(secs) * time.Second
		}
	}
	apiHandler.StartVerificationPoller(ctx, pollInterval)

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           apiHandler.BuildRouter(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("api listening", "addr", cfg.HTTPAddr, "version", version.Version)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return err
	}
	logger.Info("api stopped")
	return nil
}

// txtLookup builds the TXT lookup for domain verification: public
// resolvers when configured, else the system resolver.
func txtLookup(cfg *config.Config) dns.TXTLookup {
	if len(cfg.DNSResolvers) > 0 {
		return dns.NewTXTLookup(cfg.DNSResolvers)
	}
	return dns.DefaultTXTLookup
}

// loadAccessProvider builds the external-access provider for the API:
// env-configured Cloudflare credentials take precedence; otherwise the
// provider stored (encrypted) by the wizard is decrypted and rebuilt;
// manual is the fallback for a never-onboarded installation.
func loadAccessProvider(ctx context.Context, st *store.Store, cfg *config.Config) (access.Provider, error) {
	if cfg.Cloudflare.APIToken != "" && cfg.Cloudflare.ZoneID != "" {
		return access.New("cloudflare", access.Config{
			APIToken: cfg.Cloudflare.APIToken,
			ZoneID:   cfg.Cloudflare.ZoneID,
		})
	}
	inst, err := st.GetInstallation(ctx)
	if err != nil {
		return nil, fmt.Errorf("load installation: %w", err)
	}
	name := inst.AccessProvider
	if name == "" || name == "manual" {
		return access.New("manual", access.Config{})
	}
	sealed, err := st.GetInstallationConfig(ctx)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("load provider config: %w", err)
	}
	cfgStr := ""
	if len(sealed) > 0 {
		plain, derr := httpapi.DecryptSecret(cfg.SessionSecret, sealed)
		if derr != nil {
			return nil, fmt.Errorf("decrypt provider config: %w", derr)
		}
		cfgStr = plain
	}
	var pcfg access.Config
	if cfgStr != "" {
		if jerr := json.Unmarshal([]byte(cfgStr), &pcfg); jerr != nil {
			return nil, fmt.Errorf("parse provider config: %w", jerr)
		}
	}
	return access.New(name, pcfg)
}

// Command api runs the platform HTTP API.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"selfu/internal/auth"
	"selfu/internal/authentik"
	"selfu/internal/chasquid"
	"selfu/internal/config"
	"selfu/internal/dns"
	"selfu/internal/httpapi"
	"selfu/internal/store"
	"selfu/internal/version"
)

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

	// DNS provider: Manual by default; Cloudflare when configured (G3).
	var dnsProvider dns.Provider = dns.ManualProvider{}
	if cfg.Cloudflare.APIToken != "" && cfg.Cloudflare.ZoneID != "" {
		dnsProvider = dns.NewCloudflare(dns.CloudflareConfig{
			APIToken: cfg.Cloudflare.APIToken,
			ZoneID:   cfg.Cloudflare.ZoneID,
		})
	}

	// Chasquid controller (G4); nil when the agent is not configured.
	var chasquidCtrl chasquid.ChasquidController
	if cfg.Mail.AgentURL != "" && cfg.Mail.AgentToken != "" {
		chasquidCtrl = chasquid.NewAgentClient(cfg.Mail.AgentURL, cfg.Mail.AgentToken)
	}

	srv := &http.Server{
		Addr: cfg.HTTPAddr,
		Handler: httpapi.New(httpapi.Deps{
			Logger:         logger,
			Sessions:       sessions,
			OIDC:           prov,
			Users:          st,
			Audit:          st,
			OIDCConfig:     cfg.OIDC,
			AfterLoginPath: cfg.AfterLoginPath,
			IdentityStore:  st,
			Identity:       ak,
			ProviderName:   cfg.OIDC.Issuer,
			DomainStore:    st,
			DNSProvider:    dnsProvider,
			TXTLookup:      dns.DefaultTXTLookup,
			MailStore:      st,
			Recon:          st,
			Chasquid:       chasquidCtrl,
			MailProvision:  chasquidCtrl,
			Apps:           st,
		}),
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

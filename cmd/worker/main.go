// Command worker runs the background reconciliation loop (spec §21): it
// periodically realigns the platform's desired state (PostgreSQL) with the
// observed state of external systems. All operations are idempotent and
// conservative (spec §92). Retries happen on the next tick; failures are
// logged and audited, never destructive.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"selfu/internal/authentik"
	"selfu/internal/chasquid"
	"selfu/internal/config"
	"selfu/internal/recon"
	"selfu/internal/store"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("worker fatal", "err", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	interval := 30 * time.Second
	if v := os.Getenv("SELFU_RECONCILE_INTERVAL"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
			interval = time.Duration(secs) * time.Second
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(ctx, cfg.DBURL)
	if err != nil {
		return err
	}
	defer st.Close()

	var controller chasquid.ChasquidController
	if cfg.Mail.AgentURL != "" && cfg.Mail.AgentToken != "" {
		controller = chasquid.NewAgentClient(cfg.Mail.AgentURL, cfg.Mail.AgentToken)
	} else {
		logger.Warn("chasquid controller not configured; mail reconciliation disabled")
	}

	ak := authentik.New(cfg.Authentik.BaseURL, cfg.Authentik.Token, cfg.Authentik.TLSInsecure)

	rec := &recon.MailReconciler{
		Store:    st,
		Chasquid: controller,
		Audit:    st,
		Logger:   logger,
	}

	logger.Info("worker starting", "interval", interval.String())
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Run immediately, then on each tick.
	if err := reconcileOnce(ctx, st, rec, logger, controller != nil); err != nil {
		logger.Error("initial reconciliation failed", "err", err)
	}
	if err := recon.SyncExternal(ctx, st, ak, cfg.OIDC.Issuer, logger); err != nil {
		logger.Error("initial external-resource sync failed", "err", err)
	}

	for {
		select {
		case <-ctx.Done():
			logger.Info("worker stopped")
			return nil
		case <-ticker.C:
			if err := reconcileOnce(ctx, st, rec, logger, controller != nil); err != nil {
				// Conservative failure mode: never abort the loop.
				logger.Error("reconciliation cycle failed", "err", err)
			}
			if err := recon.SyncExternal(ctx, st, ak, cfg.OIDC.Issuer, logger); err != nil {
				logger.Error("external-resource sync cycle failed", "err", err)
			}
		}
	}
}

// reconcileOnce reconciles every active mail domain.
func reconcileOnce(ctx context.Context, st store.Recon, rec *recon.MailReconciler, logger *slog.Logger, mailEnabled bool) error {
	domains, err := st.ListActiveMailDomains(ctx)
	if err != nil {
		return err
	}
	for _, md := range domains {
		if !mailEnabled {
			break
		}
		res, err := rec.ReconcileDomain(ctx, md.DomainID, md.FQDN, md.OrganizationID)
		if err != nil {
			logger.Error("mail reconcile failed", "err", err, "domain", md.FQDN)
			continue
		}
		if res.AliasesRestored+res.GroupAliases+len(res.MissingUsers) > 0 {
			logger.Info("mail reconcile applied",
				"domain", md.FQDN,
				"aliases_restored", res.AliasesRestored+res.GroupAliases,
				"missing_users", len(res.MissingUsers))
		}
	}
	return nil
}

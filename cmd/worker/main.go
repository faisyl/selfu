// Command worker runs the background reconciliation loop (spec §21): it
// periodically realigns the platform's desired state (PostgreSQL) with the
// observed state of external systems. All operations are idempotent and
// conservative (spec §92). Retries happen on the next tick; failures are
// logged and audited, never destructive.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"selfu/internal/authentik"
	"selfu/internal/chasquid"
	"selfu/internal/config"
	"selfu/internal/domain"
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
	if err := syncExternalResources(ctx, st, ak, cfg.OIDC.Issuer, logger); err != nil {
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
			if err := syncExternalResources(ctx, st, ak, cfg.OIDC.Issuer, logger); err != nil {
				logger.Error("external-resource sync cycle failed", "err", err)
			}
		}
	}
}

// syncExternalResources verifies each external_resources mapping against the
// provider and records observed state + hash (spec §22). Missing resources
// are marked failed — never auto-removed (spec §92). authentik_application
// rows are verified through their sibling authentik_provider row: authentik
// only surfaces applications bound to the current brand's outpost, so the
// application wrapper can 404 while its provider (the auth boundary) is
// healthy — the provider check is the meaningful one.
func syncExternalResources(ctx context.Context, st store.Recon, ak *authentik.Client, provider string, logger *slog.Logger) error {
	rows, err := st.ListExternalResourcesByProvider(ctx, provider)
	if err != nil {
		return err
	}
	providerByObject := map[string]string{} // platform_object_id -> provider pk
	for _, res := range rows {
		if res.ResourceType == domain.ResTypeAuthentikProvider {
			providerByObject[res.PlatformObjectID] = res.ExternalID
		}
	}
	for _, res := range rows {
		hash := observedHash(res.ResourceType, res.ExternalID)
		checkType, checkID := res.ResourceType, res.ExternalID
		if res.ResourceType == domain.ResTypeAuthentikApplication {
			if pk, ok := providerByObject[res.PlatformObjectID]; ok {
				checkType, checkID = domain.ResTypeAuthentikProvider, pk
			}
		}
		ok, err := ak.ResourceExists(ctx, checkType, checkID)
		if err != nil {
			logger.Warn("external exists check failed", "err", err, "type", res.ResourceType, "external_id", res.ExternalID)
			continue
		}
		if ok {
			_ = st.SetExternalObserved(ctx, res.ID, domain.ExtActive, hash, "")
		} else {
			_ = st.SetExternalObserved(ctx, res.ID, domain.ExtFailed, hash, "resource missing in provider")
			logger.Warn("external resource missing in provider",
				"type", res.ResourceType, "external_id", res.ExternalID, "platform_object_id", res.PlatformObjectID)
		}
	}
	return nil
}

func observedHash(resourceType, externalID string) string {
	h := sha256.Sum256([]byte(resourceType + ":" + externalID))
	return hex.EncodeToString(h[:])
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

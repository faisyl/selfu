// Package recon reconciles the platform's desired state (PostgreSQL) with
// the observed state of external systems (spec §21). All operations are
// idempotent and conservative (spec §92): aliases are restored, missing
// users are flagged — never recreated (credentials are fingerprints only).
package recon

import (
	"context"
	"log/slog"

	"selfu/internal/chasquid"
	"selfu/internal/domain"
	"selfu/internal/store"
)

// MailReconciler realigns one mail domain's aliases and users against the
// store's desired state and chasquid's observed state. It consumes the
// store-owned interfaces (store.Recon embeds MailStore + GroupStore) so the
// same reconciler serves the API's on-demand route and the worker.
type MailReconciler struct {
	Store        store.Recon
	Chasquid     chasquid.ChasquidController
	Audit        store.AuditStore
	Logger       *slog.Logger
	ProviderName string
}

// MailResult is the outcome of one domain pass.
type MailResult struct {
	DomainID        string
	AliasesRestored int
	GroupAliases    int
	MissingUsers    []string
}

// ReconcileDomain performs one idempotent, conservative pass over a domain.
func (r *MailReconciler) ReconcileDomain(ctx context.Context, domainID, fqdn, orgID string) (MailResult, error) {
	var res MailResult
	res.DomainID = domainID

	aliases, err := r.Store.ListMailAliasesByDomain(ctx, domainID)
	if err != nil {
		return res, err
	}
	for _, a := range aliases {
		if a.Status != "active" {
			continue
		}
		if a.GroupID != nil {
			members, err := r.Store.ListGroupMembers(ctx, *a.GroupID)
			if err != nil {
				r.Logger.Warn("group members lookup failed", "err", err, "alias", a.Address)
				continue
			}
			userIDs := make([]string, 0, len(members))
			for _, m := range members {
				userIDs = append(userIDs, m.UserID)
			}
			identities, err := r.Store.ListMailIdentitiesByUsers(ctx, orgID, userIDs)
			if err != nil {
				r.Logger.Warn("group identities lookup failed", "err", err, "alias", a.Address)
				continue
			}
			var dests []string
			for _, idn := range identities {
				dests = append(dests, idn.Address)
			}
			if err := r.Store.UpdateMailAliasDestinations(ctx, a.ID, dests); err != nil {
				r.Logger.Warn("update group alias destinations failed", "err", err, "alias", a.Address)
			}
			if err := r.Chasquid.EnsureAlias(ctx, fqdn, a.LocalPart, dests); err != nil {
				r.Logger.Warn("group alias reconcile failed", "err", err, "address", a.Address)
				continue
			}
			res.GroupAliases++
			continue
		}
		if err := r.Chasquid.EnsureAlias(ctx, fqdn, a.LocalPart, a.Destinations); err != nil {
			r.Logger.Warn("alias reconcile failed", "err", err, "address", a.Address)
			continue
		}
		res.AliasesRestored++
	}
	_ = r.Chasquid.Reload(ctx)

	identities, err := r.Store.ListMailIdentitiesByDomain(ctx, domainID)
	if err != nil {
		return res, err
	}
	for _, idn := range identities {
		if idn.Status != domain.MailIdentityActive {
			continue
		}
		ok, err := r.Chasquid.UserExists(ctx, idn.Address)
		if err != nil {
			continue
		}
		if !ok {
			res.MissingUsers = append(res.MissingUsers, idn.Address)
			_ = r.Store.SetMailIdentityStatus(ctx, idn.ID, domain.MailIdentitySuspended)
			if r.Audit != nil {
				_ = r.Audit.CreateAuditEvent(ctx, domain.AuditEvent{
					Action:       "mail.identity.reconciliation_failed",
					ResourceType: "mail_identity",
					ResourceID:   idn.ID,
					Details:      map[string]any{"address": idn.Address, "reason": "chasquid user missing"},
				})
			}
		}
	}
	return res, nil
}

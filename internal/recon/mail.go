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
)

// MailStore is the mail persistence surface the reconciler needs.
type MailStore interface {
	ListMailAliasesByDomain(ctx context.Context, domainID string) ([]domain.MailAlias, error)
	ListMailIdentitiesByDomain(ctx context.Context, domainID string) ([]domain.MailIdentity, error)
	UpdateMailAliasDestinations(ctx context.Context, id string, destinations []string) error
	SetMailIdentityStatus(ctx context.Context, id, status string) error
	ListMailIdentitiesByUsers(ctx context.Context, orgID string, userIDs []string) ([]domain.MailIdentity, error)
}

// GroupStore provides group membership for group-bound aliases (§42–43).
type GroupStore interface {
	ListGroupMembers(ctx context.Context, groupID string) ([]GroupMember, error)
}

// GroupMember is a minimal group membership.
type GroupMember struct {
	UserID string
}

// AuditWriter persists reconciliation events.
type AuditWriter interface {
	CreateAuditEvent(ctx context.Context, e domain.AuditEvent) error
}

// MailReconciler realigns one mail domain's aliases and users.
type MailReconciler struct {
	Mail         MailStore
	GroupMembers func(ctx context.Context, groupID string) ([]string, error)
	Chasquid     chasquid.ChasquidController
	Audit        AuditWriter
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

	aliases, err := r.Mail.ListMailAliasesByDomain(ctx, domainID)
	if err != nil {
		return res, err
	}
	for _, a := range aliases {
		if a.Status != "active" {
			continue
		}
		if a.GroupID != nil {
			userIDs, err := r.GroupMembers(ctx, *a.GroupID)
			if err != nil {
				r.Logger.Warn("group members lookup failed", "err", err, "alias", a.Address)
				continue
			}
			identities, err := r.Mail.ListMailIdentitiesByUsers(ctx, orgID, userIDs)
			if err != nil {
				r.Logger.Warn("group identities lookup failed", "err", err, "alias", a.Address)
				continue
			}
			var dests []string
			for _, idn := range identities {
				dests = append(dests, idn.Address)
			}
			if err := r.Mail.UpdateMailAliasDestinations(ctx, a.ID, dests); err != nil {
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

	identities, err := r.Mail.ListMailIdentitiesByDomain(ctx, domainID)
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
			_ = r.Mail.SetMailIdentityStatus(ctx, idn.ID, domain.MailIdentitySuspended)
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

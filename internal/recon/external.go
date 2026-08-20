package recon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"

	"selfu/internal/domain"
)

// ExistenceChecker reports whether an external resource still exists in the
// provider (spec §22). authentik.Client satisfies it. A test fake implements
// the same interface, so SyncExternal is testable at the seam without a live
// provider.
type ExistenceChecker interface {
	ResourceExists(ctx context.Context, resourceType, externalID string) (bool, error)
}

// ExternalStore is the narrow persistence surface SyncExternal needs. The
// store module provides an adapter (store.Recon ⊇ ExternalStore); a test
// fake is the second adapter, which keeps the seam honest (two adapters).
type ExternalStore interface {
	ListExternalResourcesByProvider(ctx context.Context, provider string) ([]domain.ExternalResource, error)
	SetExternalObserved(ctx context.Context, id, status, observedHash, lastErr string) error
}

// SyncExternal verifies each external_resources mapping against the provider
// and records observed state + observed hash (spec §22). Missing resources
// are marked failed — never auto-removed (spec §92).
//
// authentik_application rows are verified through their sibling
// authentik_provider row: authentik only surfaces applications bound to the
// current brand's outpost, so the application wrapper can 404 while its
// provider (the auth boundary) is healthy — the provider check is the
// meaningful one.
func SyncExternal(ctx context.Context, st ExternalStore, check ExistenceChecker, provider string, logger *slog.Logger) error {
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
		ok, err := check.ResourceExists(ctx, checkType, checkID)
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

// ProviderFor returns the provider label used by the worker to scope the
// external-resource sync (the OIDC issuer).
func ProviderFor(issuer string) string { return issuer }

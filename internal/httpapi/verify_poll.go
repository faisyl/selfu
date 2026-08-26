package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"selfu/internal/dns"
	"selfu/internal/domain"
)

// This file closes the onboarding auto-verify loop: the exact verification
// logic used by POST /setup/verify (runVerifySetup, extracted verbatim
// from verifySetup) is also driven by a background poller so the operator
// does not have to keep the wizard page open.

// runVerifySetup performs one full primary-domain verification attempt
// with the same semantics as the wizard endpoint. actorID identifies the
// acting admin for auditing ("" for the system poller). It returns the
// HTTP status the endpoint would render plus its JSON payload.
func (h *Handler) runVerifySetup(ctx context.Context, actorID string) (int, map[string]any) {
	inst, err := h.d.Setup.GetInstallation(ctx)
	if err != nil {
		return http.StatusInternalServerError, map[string]any{"error": "internal_error"}
	}
	if inst.Onboarded() {
		return http.StatusConflict, map[string]any{"error": "already_onboarded"}
	}
	if inst.PrimaryDomainID == "" {
		return http.StatusConflict, map[string]any{"error": "no_primary_domain"}
	}
	d, err := h.d.DomainStore.GetDomainByID(ctx, inst.PrimaryDomainID)
	if err != nil {
		return http.StatusNotFound, map[string]any{"error": "not_found"}
	}
	if d.Status == domain.DomainVerified {
		// Already verified; completing is idempotent.
		if err := h.d.Setup.SetInstallationOnboarded(ctx, time.Now().UTC()); err != nil {
			return http.StatusInternalServerError, map[string]any{"error": "internal_error"}
		}
		return http.StatusOK, map[string]any{"status": string(domain.DomainVerified), "onboarded": true}
	}

	recordName := dns.VerifyRecordName(d.FQDN)
	recordValue := dns.TokenTXTValue(d.VerificationToken)
	if h.d.TXTLookup == nil {
		return http.StatusInternalServerError, map[string]any{"error": "internal_error"}
	}
	txts, err := h.d.TXTLookup(ctx, recordName)
	if err != nil {
		_ = h.d.DomainStore.LogVerification(ctx, d.ID, d.VerificationMethod, err.Error(), false)
		return http.StatusUnprocessableEntity, map[string]any{"error": "lookup_failed"}
	}
	verified := false
	for _, t := range txts {
		if t == recordValue {
			verified = true
			break
		}
	}
	if !verified {
		_ = h.d.DomainStore.LogVerification(ctx, d.ID, d.VerificationMethod, "record not found", false)
		return http.StatusOK, map[string]any{
			"status":   string(d.Status),
			"verified": false,
			"hint":     "set TXT " + recordName + " to " + recordValue,
		}
	}

	now := time.Now().UTC()
	if err := h.d.DomainStore.SetDomainStatus(ctx, d.ID, domain.DomainVerified, &now); err != nil {
		return http.StatusInternalServerError, map[string]any{"error": "internal_error"}
	}
	_ = h.d.DomainStore.LogVerification(ctx, d.ID, d.VerificationMethod, "verified", true)
	if err := h.d.Setup.SetInstallationOnboarded(ctx, now); err != nil {
		return http.StatusInternalServerError, map[string]any{"error": "internal_error"}
	}
	var actor *string
	if actorID != "" {
		actor = &actorID
	}
	h.audit(ctx, domain.AuditEvent{
		ActorUserID:  actor,
		Action:       "setup.onboarded",
		ResourceType: "domain",
		ResourceID:   d.ID,
		Details:      map[string]any{"fqdn": d.FQDN},
	})
	return http.StatusOK, map[string]any{"status": string(domain.DomainVerified), "onboarded": true}
}

// StartVerificationPoller launches the background auto-verify loop: while
// the installation is not yet onboarded and has a pending primary domain,
// it periodically re-checks the verification TXT and completes onboarding
// on success. The loop stops when ctx is cancelled or once onboarded.
func (h *Handler) StartVerificationPoller(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if h.pollVerificationOnce(ctx) {
					return
				}
			}
		}
	}()
}

// pollVerificationOnce runs one auto-verify cycle. It reports whether the
// installation is now onboarded (the loop can stop).
func (h *Handler) pollVerificationOnce(ctx context.Context) bool {
	inst, err := h.d.Setup.GetInstallation(ctx)
	if err != nil {
		h.noteVerifyPoll("installation lookup failed: " + err.Error())
		return false
	}
	if inst.Onboarded() {
		return true
	}
	if inst.PrimaryDomainID == "" {
		return false // nothing pending yet; keep watching
	}
	code, payload := h.runVerifySetup(ctx, "")
	note := fmt.Sprintf("attempt status %d", code)
	if s, ok := payload["status"].(string); ok {
		note += ": " + s
	} else if e, ok := payload["error"].(string); ok {
		note += ": " + e
	}
	if hint, ok := payload["hint"].(string); ok && !payloadBool(payload, "verified") {
		note += " (" + hint + ")"
	}
	h.noteVerifyPoll(note)
	return payloadBool(payload, "onboarded")
}

func payloadBool(m map[string]any, key string) bool {
	v, _ := m[key].(bool)
	return v
}

func (h *Handler) noteVerifyPoll(result string) {
	h.pollMu.Lock()
	defer h.pollMu.Unlock()
	h.lastVerifyCheck = time.Now().UTC()
	h.lastVerifyResult = result
}

// verifySnapshot returns the last background auto-verify attempt (zero
// time before the first tick).
func (h *Handler) verifySnapshot() (time.Time, string) {
	h.pollMu.Lock()
	defer h.pollMu.Unlock()
	return h.lastVerifyCheck, h.lastVerifyResult
}

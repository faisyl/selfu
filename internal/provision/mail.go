// Package provision deepens the platform's identity-credential provisioning:
// one module owns the sequence secret → mail identity → credential
// (fingerprint) → chasquid user → sender policy → policy row → status, so
// the two call sites (mailbox creation, application SMTP identity) stop
// hand-rolling the same 7 steps.
package provision

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"selfu/internal/chasquid"
	"selfu/internal/domain"
)

// Store is the persistence surface the provisioner needs.
// Store is the persistence surface the provisioner needs (identity, credential,
// policy row, status, credential revocation).
type Store interface {
	CreateMailIdentity(ctx context.Context, m domain.MailIdentity) (domain.MailIdentity, error)
	CreateMailCredential(ctx context.Context, c domain.MailCredential) (domain.MailCredential, error)
	CreateMailSubmissionPolicy(ctx context.Context, p domain.MailSubmissionPolicy) error
	SetMailIdentityStatus(ctx context.Context, id, status string) error
	RevokeCredentialsByIdentity(ctx context.Context, identityID string) error
}

// Mail is the sole seam: Provisioner + ChasquidMTA (the controller) satisfy
// it; the httpapi handler implements the same interface, so tests cross the
// same seam as prod callers.
// Mail is the MTA seam (AddUser + sender policy + password change). The
// chasquid controller satisfies it; a fake in tests crosses the same seam.
type Mail interface {
	AddUser(ctx context.Context, address string, password chasquid.Secret) error
	EnsureSenderPolicy(ctx context.Context, authUser string, allowedFrom []string) error
	ChangePassword(ctx context.Context, address string, password chasquid.Secret) error
}

// Provisioner deepens mailbox provisioning: one call produces a mail identity
// plus its first credential (secret shown once), wired into chasquid with the
// sender policy. Returns the identity, the credential id, and the secret.
func Provisioner(ctx context.Context, st Store, mta Mail, m domain.MailIdentity) (domain.MailIdentity, string, chasquid.Secret, error) {
	secret, err := newSMTPSecret()
	if err != nil {
		return domain.MailIdentity{}, "", "", err
	}
	if m.LocalPart == "" && m.Address != "" {
		m.LocalPart = strings.SplitN(m.Address, "@", 2)[0]
	}
	if m.Status == "" {
		m.Status = domain.MailIdentityProvisioning
	}
	ident, err := st.CreateMailIdentity(ctx, m)
	if err != nil {
		return domain.MailIdentity{}, "", "", fmt.Errorf("create mail identity: %w", err)
	}
	cred, err := st.CreateMailCredential(ctx, domain.MailCredential{
		MailIdentityID:    ident.ID,
		SecretFingerprint: fingerprint(secret),
	})
	if err != nil {
		return domain.MailIdentity{}, "", "", fmt.Errorf("create mail credential: %w", err)
	}
	if err := mta.AddUser(ctx, ident.Address, secret); err != nil {
		_ = st.SetMailIdentityStatus(ctx, ident.ID, domain.MailIdentityDeleted)
		return domain.MailIdentity{}, "", "", fmt.Errorf("chasquid add user: %w", err)
	}
	if err := mta.EnsureSenderPolicy(ctx, ident.Address, []string{ident.Address}); err != nil {
		// Non-fatal: the post-data hook keeps the identity locked to its own
		// address even if the policy file install lags a tick.
		_ = err
	}
	_ = st.CreateMailSubmissionPolicy(ctx, domain.MailSubmissionPolicy{
		MailIdentityID:       ident.ID,
		CredentialID:         cred.ID,
		AllowedFromAddresses: []string{ident.Address},
	})
	_ = st.SetMailIdentityStatus(ctx, ident.ID, domain.MailIdentityActive)
	ident.Status = domain.MailIdentityActive
	return ident, cred.ID, secret, nil
}

// Rotate issues a fresh credential for an existing identity: chasquid
// password change, revoke the old credential, record the new fingerprint.
func Rotate(ctx context.Context, st Store, mta Mail, identity domain.MailIdentity) (string, chasquid.Secret, error) {
	secret, err := newSMTPSecret()
	if err != nil {
		return "", "", err
	}
	if err := mta.ChangePassword(ctx, identity.ChasquidUsername, secret); err != nil {
		return "", "", fmt.Errorf("chasquid change password: %w", err)
	}
	if err := st.RevokeCredentialsByIdentity(ctx, identity.ID); err != nil {
		return "", "", fmt.Errorf("revoke credentials: %w", err)
	}
	cred, err := st.CreateMailCredential(ctx, domain.MailCredential{
		MailIdentityID:    identity.ID,
		SecretFingerprint: fingerprint(secret),
	})
	if err != nil {
		return "", "", fmt.Errorf("create mail credential: %w", err)
	}
	return cred.ID, secret, nil
}

func newSMTPSecret() (chasquid.Secret, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	s := base64.RawURLEncoding.EncodeToString(b)
	if len(s) < 24 {
		return "", errors.New("generated secret too short")
	}
	return chasquid.Secret(s), nil
}

func fingerprint(s chasquid.Secret) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

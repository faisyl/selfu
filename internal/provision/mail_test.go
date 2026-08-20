package provision

import (
	"context"
	"testing"

	"selfu/internal/chasquid"
	"selfu/internal/domain"
)

type fakeStore struct {
	nextID    int
	created   []domain.MailIdentity
	creds     []domain.MailCredential
	policies  []domain.MailSubmissionPolicy
	statuses  []string
	revoked   string
	errCreate error
}

func (f *fakeStore) CreateMailIdentity(_ context.Context, m domain.MailIdentity) (domain.MailIdentity, error) {
	if f.errCreate != nil {
		return domain.MailIdentity{}, f.errCreate
	}
	f.nextID++
	m.ID = "id-1"
	f.created = append(f.created, m)
	if m.Status == "" {
		m.Status = domain.MailIdentityProvisioning
	}
	return m, nil
}
func (f *fakeStore) CreateMailCredential(_ context.Context, c domain.MailCredential) (domain.MailCredential, error) {
	f.nextID++
	c.ID = "cred-1"
	f.creds = append(f.creds, c)
	return c, nil
}
func (f *fakeStore) CreateMailSubmissionPolicy(_ context.Context, p domain.MailSubmissionPolicy) error {
	f.policies = append(f.policies, p)
	return nil
}
func (f *fakeStore) SetMailIdentityStatus(_ context.Context, _, status string) error {
	f.statuses = append(f.statuses, status)
	return nil
}
func (f *fakeStore) RevokeCredentialsByIdentity(_ context.Context, id string) error {
	f.revoked = id
	return nil
}

type fakeMail struct {
	users    []string
	policies []string
	secret   chasquid.Secret
}

func (f *fakeMail) AddUser(_ context.Context, address string, password chasquid.Secret) error {
	f.users = append(f.users, address)
	f.secret = password
	return nil
}
func (f *fakeMail) EnsureSenderPolicy(_ context.Context, user string, _ []string) error {
	f.policies = append(f.policies, user)
	return nil
}
func (f *fakeMail) ChangePassword(_ context.Context, address string, password chasquid.Secret) error {
	return nil
}

// TestProvisionerFullSequence: one call produces identity + credential
// (fingerprint, not plaintext) + chasquid user + sender policy + policy row +
// active status — the whole 7-step sequence now in one module.
func TestProvisionerFullSequence(t *testing.T) {
	f := &fakeStore{}
	m := &fakeMail{}
	ident, credID, secret, err := Provisioner(context.Background(), f, m, domain.MailIdentity{
		OrganizationID: "org", DomainID: "dom", Address: "alice@example.com", ChasquidUsername: "alice@example.com",
	})
	if err != nil {
		t.Fatalf("Provisioner: %v", err)
	}
	if ident.Address != "alice@example.com" {
		t.Errorf("address = %q", ident.Address)
	}
	if ident.Status != domain.MailIdentityActive {
		t.Errorf("identity status = %q, want active", ident.Status)
	}
	if len(f.creds) != 1 || f.creds[0].SecretFingerprint == "" {
		t.Fatal("credential with fingerprint required")
	}
	if credID == "" {
		t.Error("credential id must be returned")
	}
	if string(f.creds[0].SecretFingerprint) == string(secret) {
		t.Error("fingerprint must not be the plaintext secret")
	}
	if secret == "" || len(string(secret)) < 20 {
		t.Errorf("secret too short: %q", string(secret))
	}
	if len(m.users) != 1 || m.users[0] != "alice@example.com" {
		t.Errorf("mta users = %v", m.users)
	}
	if len(f.policies) != 1 || f.policies[0].AllowedFromAddresses[0] != "alice@example.com" {
		t.Error("sender policy row required")
	}
	if len(f.statuses) != 1 || f.statuses[0] != domain.MailIdentityActive {
		t.Errorf("status transitions = %v", f.statuses)
	}
}

// TestRotateRevokesOldAndReturnsNew: rotation revokes the old credential and
// issues a fresh one.
func TestRotateRevokesOldAndReturnsNew(t *testing.T) {
	f := &fakeStore{}
	m := &fakeMail{}
	_, _, err := Rotate(context.Background(), f, m, domain.MailIdentity{ID: "ident-1", ChasquidUsername: "alice@example.com"})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if f.revoked != "ident-1" {
		t.Errorf("revoked = %q, want ident-1", f.revoked)
	}
}

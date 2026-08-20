package store

import (
	"context"
	"time"

	"selfu/internal/catalog"
	"selfu/internal/domain"
)

// The store module owns the interfaces for its persistence surfaces. Callers
// (httpapi, recon, worker) depend on these instead of re-declaring per-handler
// interface copies, so a method change is edited here and nowhere else.
//
// *Store satisfies every interface below; the assertions at the bottom lock
// that in at compile time.

// UserStore is the user persistence surface.
type UserStore interface {
	UpsertFromOIDC(ctx context.Context, provider, subject, email, displayName string) (domain.User, bool, bool, error)
	GetByID(ctx context.Context, id string) (domain.User, error)
}

// AuditStore persists and lists audit events.
type AuditStore interface {
	CreateAuditEvent(ctx context.Context, e domain.AuditEvent) error
	ListAuditEvents(ctx context.Context, limit int) ([]domain.AuditEvent, error)
}

// IdentityStore is the identity persistence surface (users, orgs, memberships,
// groups, external resources).
type IdentityStore interface {
	CreateOrganization(ctx context.Context, o domain.Organization) (domain.Organization, error)
	GetOrganizationByID(ctx context.Context, id string) (domain.Organization, error)
	ListOrganizations(ctx context.Context, limit int) ([]domain.Organization, error)
	DeleteOrganization(ctx context.Context, id string) error

	SetMembership(ctx context.Context, orgID, userID string, role domain.OrgRole) (domain.OrganizationMembership, error)
	GetMembershipRole(ctx context.Context, orgID, userID string) (domain.OrgRole, error)
	ListMemberships(ctx context.Context, orgID string) ([]Member, error)
	RemoveMembership(ctx context.Context, orgID, userID string) error
	RemoveAllMemberships(ctx context.Context, userID string) error

	CreateGroup(ctx context.Context, g domain.Group) (domain.Group, error)
	GetGroupByID(ctx context.Context, id string) (domain.Group, error)
	ListGroupsByOrg(ctx context.Context, orgID string) ([]domain.Group, error)
	DeleteGroup(ctx context.Context, id string) error
	AddGroupMember(ctx context.Context, groupID, userID string) error
	RemoveGroupMember(ctx context.Context, groupID, userID string) error
	RemoveAllGroupMemberships(ctx context.Context, userID string) error
	ListGroupMembers(ctx context.Context, groupID string) ([]GroupMember, error)

	GetUserByEmail(ctx context.Context, email string) (domain.User, error)
	CreateUser(ctx context.Context, email, displayName, authProvider, authIdentityID string) (domain.User, error)
	SetUserStatus(ctx context.Context, id string, status domain.UserStatus) error
	ListUsers(ctx context.Context, limit int) ([]domain.User, error)

	UpsertExternalResource(ctx context.Context, res domain.ExternalResource) (domain.ExternalResource, error)
	GetExternalResource(ctx context.Context, resourceType, platformObjectID string) (domain.ExternalResource, error)
	SetExternalStatus(ctx context.Context, id, status, lastErr string) error
}

// DomainStore is the domain/hostname persistence surface.
type DomainStore interface {
	CreateDomain(ctx context.Context, d domain.Domain) (domain.Domain, error)
	GetDomainByID(ctx context.Context, id string) (domain.Domain, error)
	GetDomainByOrgFQDN(ctx context.Context, orgID, fqdn string) (domain.Domain, error)
	ListDomainsByOrg(ctx context.Context, orgID string) ([]domain.Domain, error)
	SetDomainStatus(ctx context.Context, id string, status domain.DomainStatus, verifiedAt *time.Time) error
	LogVerification(ctx context.Context, domainID, method, detail string, success bool) error
	DeleteDomain(ctx context.Context, id string) error

	AddHostname(ctx context.Context, h domain.Hostname) (domain.Hostname, error)
	GetHostnameByID(ctx context.Context, id string) (domain.Hostname, error)
	ListHostnamesByDomain(ctx context.Context, domainID string) ([]domain.Hostname, error)
	RemoveHostname(ctx context.Context, id string) error
}

// MailStore is the mail persistence surface.
type MailStore interface {
	CreateMailDomain(ctx context.Context, domainID string) (domain.MailDomain, error)
	GetMailDomainByDomainID(ctx context.Context, domainID string) (domain.MailDomain, error)
	SetMailDomainStatus(ctx context.Context, id string, status domain.MailDomainStatus) error
	SetMailDomainDKIM(ctx context.Context, id, selector, record string) error

	CreateMailIdentity(ctx context.Context, m domain.MailIdentity) (domain.MailIdentity, error)
	GetMailIdentity(ctx context.Context, id string) (domain.MailIdentity, error)
	GetMailIdentityByAddress(ctx context.Context, address string) (domain.MailIdentity, error)
	ListMailIdentitiesByDomain(ctx context.Context, domainID string) ([]domain.MailIdentity, error)
	SetMailIdentityStatus(ctx context.Context, id, status string) error

	CreateMailCredential(ctx context.Context, c domain.MailCredential) (domain.MailCredential, error)
	RevokeCredentialsByIdentity(ctx context.Context, identityID string) error

	CreateMailAlias(ctx context.Context, a domain.MailAlias) (domain.MailAlias, error)
	GetMailAliasByAddress(ctx context.Context, address string) (domain.MailAlias, error)
	ListMailAliasesByDomain(ctx context.Context, domainID string) ([]domain.MailAlias, error)
	UpdateMailAliasDestinations(ctx context.Context, id string, destinations []string) error
	ListMailIdentitiesByUsers(ctx context.Context, orgID string, userIDs []string) ([]domain.MailIdentity, error)
	DeleteMailAlias(ctx context.Context, id string) error

	CreateMailSubmissionPolicy(ctx context.Context, p domain.MailSubmissionPolicy) error

	ValidateAliasDestinations(ctx context.Context, orgID string, destinations []string) error
}

// AppStore is the application catalog/instance persistence surface.
type AppStore interface {
	CreateCatalogApp(ctx context.Context, m *catalog.Manifest) (string, error)
	GetCatalogAppByID(ctx context.Context, id string) (CatalogApp, error)
	ListCatalogApps(ctx context.Context) ([]CatalogApp, error)

	CreateApplicationInstance(ctx context.Context, orgID, catalogID, name, slug string) (string, error)
	GetInstance(ctx context.Context, id string) (Instance, error)
	ListInstancesByOrg(ctx context.Context, orgID string) ([]Instance, error)
	SetInstanceStatus(ctx context.Context, id, status string) error

	AddInstanceHostname(ctx context.Context, instanceID, hostname string) error
	AddInstanceAccessGroup(ctx context.Context, instanceID, groupID string) error
}

// GroupStore provides group memberships (used by the reconciler for
// group-bound aliases, spec §42).
type GroupStore interface {
	ListGroupMembers(ctx context.Context, groupID string) ([]GroupMember, error)
}

// Recon is everything the reconciliation worker needs from the store.
type Recon interface {
	MailStore
	GroupStore

	ListActiveMailDomains(ctx context.Context) ([]ActiveMailDomain, error)
	ListExternalResourcesByProvider(ctx context.Context, provider string) ([]domain.ExternalResource, error)
	SetExternalObserved(ctx context.Context, id, status, observedHash, lastErr string) error
}

// Compile-time assertions: the concrete store satisfies every owned interface.
var (
	_ UserStore     = (*Store)(nil)
	_ AuditStore    = (*Store)(nil)
	_ IdentityStore = (*Store)(nil)
	_ DomainStore   = (*Store)(nil)
	_ MailStore     = (*Store)(nil)
	_ AppStore      = (*Store)(nil)
	_ GroupStore    = (*Store)(nil)
	_ Recon         = (*Store)(nil)
)

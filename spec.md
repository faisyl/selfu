# Self-Hosted Multi-Domain Application Platform — v0.2 Technical Specification

## 1. Objective

Build a self-hosted application platform using Docker Compose as the initial deployment substrate.

The platform shall allow an administrator to:

1. Register one or more domains.
2. Verify ownership of those domains.
3. Create platform users.
4. Assign users to organizations.
5. Deploy applications from an application catalog.
6. Bind applications to arbitrary hostnames under verified domains.
7. Automatically provision TLS and HTTP routing.
8. Automatically provision authentication for applications that support OIDC.
9. Automatically protect applications that do not support native authentication using authentik forward-auth.
10. Automatically configure DNS when a supported DNS provider is available.
11. Provision email domains, mailboxes, aliases and SMTP identities through chasquid.
12. Maintain a single user/domain model shared by the application platform and mail subsystem.
13. Leave external inbound delivery and external outbound delivery as replaceable integrations to be implemented later.
14. Manage application access through platform-level groups and roles.
15. Keep the platform's desired state independent of Docker Compose, Traefik, authentik and chasquid implementation details.

The initial implementation is a single-host Docker Compose deployment.

---

# 2. Core architectural principle

The platform is the source of truth for identity and tenancy.

```text
                       PLATFORM
                           |
       +-------------------+-------------------+
       |                   |                   |
       v                   v                   v
   authentik            chasquid            applications
   identity             mail/MTA             SSO
       |                   |                   |
       +-------------------+-------------------+
                           |
                     organization
                       / domain
                         model
```

The same platform user may have:

```text
Alice
 |
 +-- Organization: Acme
 |
 +-- domains:
 |     example.com
 |     example.net
 |
 +-- application access:
 |     cloud.example.com
 |     git.example.com
 |
 +-- mail identities:
       alice@example.com
       alice@example.net
```

There must not be separate, manually maintained "application users" and "mail users" unless an application inherently requires a separate native identity.

---

# 3. Technology choices

## 3.1 Core

* Docker Engine
* Docker Compose v2
* PostgreSQL
* Go platform API
* Go background worker
* Traefik
* authentik
* chasquid

## 3.2 Future external services

External mail transport is explicitly out of scope for the initial implementation.

Future integrations may provide:

* inbound SMTP delivery
* outbound SMTP relay
* spam filtering
* reputation/queueing
* external email forwarding
* delivery webhooks

These must integrate around chasquid rather than replace the platform's mail identity model.

---

# 4. Identity architecture

Use authentik as the authentication provider.

The platform owns:

* users
* organizations
* memberships
* groups
* application authorization
* mail identities

authentik owns:

* authentication
* sessions
* OIDC
* authentication flows
* MFA
* password storage
* identity-provider functionality

chasquid owns:

* SMTP MTA functionality
* SMTP submission
* domain-specific mail routing
* local mail users
* aliases
* mail queue
* SMTP transport
* DKIM signing/verification
* mail TLS/security state

The platform coordinates all three.

---

# 5. Organization

```text
Organization
------------
id
name
slug
status
created_at
updated_at
```

An organization is the primary administrative/security boundary.

Example:

```text
Acme
 |
 +-- users
 +-- groups
 +-- domains
 +-- applications
 +-- mail identities
```

---

# 6. User

```text
User
----
id
email
display_name
status

auth_identity_id

created_at
updated_at
```

`auth_identity_id` references the corresponding authentik identity.

Do not use email as the database primary key.

A user's login email and mail identities are related but are not necessarily the same thing.

---

# 7. Organization membership

```text
OrganizationMembership
----------------------
id
organization_id
user_id
role
created_at
```

Initial roles:

```text
owner
admin
member
```

A user's organization membership determines whether they can administer:

* domains
* applications
* mail
* groups
* users

---

# 8. Groups

```text
Group
-----
id
organization_id
name
slug
description
```

Membership:

```text
GroupMembership
---------------
group_id
user_id
```

Example:

```text
Acme
 |
 +-- admins
 +-- developers
 +-- users
 +-- finance
```

Groups are used by both:

* application authorization
* mail administration policy

---

# 9. Domains

A domain is a first-class resource shared by web and mail.

```text
Domain
------
id
organization_id
fqdn

status
verification_method
verification_token
verified_at

dns_provider_id

web_enabled
mail_enabled

created_at
updated_at
```

Example:

```text
example.com
example.net
```

Only verified domains can be used for:

* public application hostnames
* mail identities
* mail aliases
* application-generated sender addresses

---

# 10. Domain lifecycle

```text
pending
   |
   v
verification_required
   |
   v
verified
   |
   +---- web_enabled
   |
   +---- mail_enabled
   |
   v
suspended
```

Domain verification is required before mail or web services can be provisioned.

---

# 11. Domain verification

Initial method:

DNS TXT.

Generate:

```text
_platform-verification.<domain>
```

with a cryptographically random token.

Example:

```text
_platform-verification.example.com
TXT "platform=<random-token>"
```

The platform verifies the TXT record before changing domain state to `verified`.

---

# 12. Hostnames

```text
Hostname
--------
id
domain_id
application_instance_id
hostname
status
```

Example:

```text
cloud.example.com
git.example.com
photos.example.com
```

The platform must ensure the hostname is actually contained within the verified domain.

Do not use naive string suffix checks.

---

# 13. Application catalog

The catalog is declarative.

Example:

```yaml
id: gitea
version: "1"

metadata:
  name: Gitea
  description: Git hosting
  category: development

deployment:
  engine: docker-compose

network:
  http:
    container_port: 3000

storage:
  - name: data
    type: persistent

database:
  type: postgres

authentication:
  mode: oidc

email:
  required: true
```

The catalog must not contain arbitrary Compose fragments.

---

# 14. Authentication modes

Applications support:

```text
oidc
forward-auth
native
none
```

Preferred order:

1. native OIDC
2. forward-auth
3. native application authentication
4. public/none only when explicitly permitted

---

# 15. Platform authentication

The platform UI itself uses authentik OIDC.

```text
Browser
   |
   v
Platform
   |
   v
authentik
   |
   v
OIDC callback
   |
   v
Platform session
```

The platform must not implement an independent password database.

---

# 16. authentik integration

Maintain mappings:

```text
Platform User
    |
    +-- authentik User

Platform Group
    |
    +-- authentik Group

Application Instance
    |
    +-- authentik Application
    +-- authentik Provider
```

Store external IDs explicitly.

Do not infer ownership from names.

---

# 17. Application authorization

Default:

```text
deny
```

Example:

```yaml
authorization:
  default: deny

  roles:
    admin:
      groups:
        - admins

    user:
      groups:
        - users
        - developers
```

The platform provisions the corresponding authentik authorization relationships.

---

# 18. Traefik

Traefik handles:

* HTTP routing
* HTTPS
* TLS certificates
* application discovery
* forward-auth
* middleware

Example generated configuration:

```yaml
labels:
  - traefik.enable=true
  - traefik.http.routers.git.rule=Host(`git.example.com`)
  - traefik.http.routers.git.entrypoints=websecure
  - traefik.http.routers.git.tls=true
```

The catalog must not be allowed to inject arbitrary Traefik configuration.

---

# 19. TLS

Use Traefik ACME integration.

Preferred:

* DNS-01 where DNS automation is available
* HTTP-01 otherwise

Certificate lifecycle belongs to Traefik.

---

# 20. Docker deployment

Each application instance receives an isolated Compose project.

Example:

```text
/var/lib/platform/
    applications/
        <instance-id>/
            compose.yaml
            env/
```

Compose project names must be generated from platform IDs, not arbitrary user input.

---

# 21. Desired-state reconciliation

The platform database contains desired state.

External systems contain observed state.

```text
desired state
     |
     v
reconciler
     |
     +-- authentik
     +-- chasquid
     +-- DNS
     +-- Traefik
     +-- Docker
```

Every operation must be idempotent.

---

# 22. External resource tracking

```text
ExternalResource
----------------
id
resource_type
platform_object_id
provider
external_id
desired_hash
observed_hash
status
last_error
created_at
updated_at
```

Examples:

```text
authentik_application
authentik_provider
dns_record
traefik_route
docker_project

chasquid_domain
chasquid_user
chasquid_alias
chasquid_certificate
```

---

# 23. Mail architecture

## 23.1 Chasquid is the platform MTA

chasquid is the initial and canonical MTA.

It must run as a first-class platform service.

chasquid is specifically designed for multiple/virtual domains with per-domain users and aliases, making its native data model a good match for the platform's domain/user model.

The platform should use chasquid's native domain/user/alias mechanisms rather than inventing an unrelated mail database.

---

# 24. Mail responsibilities

chasquid handles:

```text
SMTP port 25
SMTP submission
local domain recognition
per-domain users
aliases
mail queue
outbound SMTP transport
TLS
DKIM
SPF-related handling
MTA-STS/security tracking
```

chasquid supports per-domain TLS security tracking and prevents downgrading once a domain has demonstrated a higher security level.

chasquid also supports DKIM signing and verification directly in current versions.

---

# 25. External mail services

The initial platform does NOT implement:

```text
external inbound delivery
external outbound relay
```

Instead, design for:

```text
                    Internet
                       |
             +---------+---------+
             |                   |
       future inbound       future outbound
          service               service
             |                   ^
             v                   |
          chasquid <-------------+
             |
             +-- local mail
             +-- aliases
             +-- submission
             +-- applications
```

The platform must not require these services to exist.

---

# 26. Mail domain model

```text
MailDomain
----------
id
domain_id

chasquid_domain
status

inbound_status
outbound_status
tls_status
dkim_status

created_at
updated_at
```

The `domain_id` is the platform Domain.

There must be exactly one logical mail domain per enabled platform domain.

---

# 27. Enabling mail

API:

```text
POST /api/v1/domains/:id/mail
```

Flow:

```text
verified domain
       |
       v
enable mail
       |
       v
create chasquid domain
       |
       v
configure domain metadata
       |
       v
configure certificates
       |
       v
configure DKIM
       |
       v
publish/prepare DNS requirements
       |
       v
mail domain active
```

---

# 28. Chasquid domain layout

The chasquid configuration must use its native domain structure:

```text
/etc/chasquid/
    chasquid.conf

    domains/
        example.com/
            users
            aliases
            dkim:*.pem

        example.net/
            users
            aliases
            dkim:*.pem
```

This matches chasquid's documented configuration model.

The platform should treat these files as generated state.

Do not manually edit them after the platform takes ownership.

---

# 29. Chasquid domain provisioning

For:

```text
example.com
```

the platform must ensure:

```text
/etc/chasquid/domains/example.com/
```

exists.

Use chasquid's supported administration tools wherever possible.

`chasquid-util` supports domain/user operations and current documentation explicitly describes `user-add user@domain` as creating the corresponding domain directory when necessary.

---

# 30. Mail user model

A mail user is not a separate human identity.

It is a capability belonging to a platform user.

```text
Platform User
      |
      +-- MailIdentity
              |
              +-- address
              +-- domain
              +-- chasquid account
```

Example:

```text
Alice
 |
 +-- alice@example.com
 +-- alice@example.net
```

---

# 31. MailIdentity

```text
MailIdentity
------------
id
organization_id
user_id
domain_id

local_part
address

chasquid_username

status

created_at
updated_at
```

The canonical address is:

```text
local_part@domain
```

---

# 32. Mail identity lifecycle

```text
requested
   |
   v
provisioning
   |
   v
active
   |
   +---- suspended
   |
   v
deleted
```

When a platform user is disabled, their mail identities must be disabled according to platform policy.

Do not immediately delete the mailbox identity unless explicitly configured.

---

# 33. Chasquid user provisioning

When creating:

```text
alice@example.com
```

the platform must provision the corresponding chasquid user.

Preferred operation:

```text
chasquid-util user-add alice@example.com
```

or an equivalent controlled mechanism.

The platform must not directly manipulate the password database format unless required by chasquid's supported interfaces.

---

# 34. Mail authentication

chasquid's SMTP submission authentication is separate from web OIDC authentication.

The platform must therefore distinguish:

```text
Web identity:
    Alice -> authentik

Mail submission identity:
    alice@example.com -> chasquid
```

However, **the lifecycle of both identities is controlled by the same platform user record.**

The platform should automatically provision/revoke mail credentials when mail identities are created/suspended/deleted.

chasquid requires TLS for authenticated SMTP connections and supports SMTP clients using TLS plus PLAIN authentication.

---

# 35. Mail credential policy

Do not reuse:

```text
authentik password
```

as:

```text
chasquid SMTP password
```

Generate an independent high-entropy SMTP credential.

Store it as a platform-managed secret.

The user may be shown the credential once or be given a mechanism to rotate it.

---

# 36. Mail credential API

```text
POST /api/v1/mail-identities/:id/credentials
POST /api/v1/mail-identities/:id/credentials/rotate
DELETE /api/v1/mail-identities/:id/credentials
```

Credentials are never returned by normal GET endpoints.

---

# 37. Mail aliases

Aliases are first-class platform objects.

```text
MailAlias
---------
id
organization_id
domain_id

local_part
address

destinations[]

status
created_at
updated_at
```

Example:

```text
support@example.com
    |
    +-- alice@example.com
    +-- bob@example.com
```

chasquid supports per-domain aliases in the domain's `aliases` file.

---

# 38. Alias API

```text
POST   /api/v1/domains/:id/mail/aliases
GET    /api/v1/domains/:id/mail/aliases
PATCH  /api/v1/mail-aliases/:id
DELETE /api/v1/mail-aliases/:id
```

Example:

```json
{
  "local_part": "support",
  "destinations": [
    "alice@example.com",
    "bob@example.com"
  ]
}
```

Destinations must be validated.

---

# 39. Alias security

Prevent:

```text
cross-organization mail routing
```

unless explicitly permitted.

For example, an organization owning:

```text
example.com
```

must not automatically be able to create:

```text
support@example.com
    -> victim@other-org.example
```

unless the platform explicitly permits external alias destinations.

External forwarding should be a separate policy-controlled capability.

---

# 40. Catch-all aliases

Catch-all support should not be enabled by default.

If supported:

```text
*@example.com
```

must require explicit administrator confirmation.

Catch-all mail has significant abuse and resource implications.

---

# 41. Mail administration permissions

Initial permissions:

```text
organization owner
    - manage all mail

organization admin
    - manage mail domains
    - manage aliases
    - manage mail identities

user
    - manage own credentials
    - manage own identities if policy permits
```

A user must not be able to create arbitrary mailboxes merely because they belong to the organization.

---

# 42. Mail groups

Do not create a chasquid mailbox for every application role.

Platform groups may instead be used to provision aliases.

Example:

```text
Group:
developers

Alias:
developers@example.com

Destinations:
alice@example.com
bob@example.com
carol@example.com
```

The platform can reconcile group membership into alias destinations.

This creates a useful bridge between application authorization and mail.

---

# 43. Group-to-mail integration

Optional catalog feature:

```yaml
mail:
  identities:
    - local_part: notifications

  aliases:
    - local_part: support
      group: support
```

For example:

```text
support@example.com
        |
        v
platform group "support"
        |
        +-- Alice
        +-- Bob
```

When group membership changes, the platform reconciles the alias.

---

# 44. Application mail identities

Applications may request a platform-managed sender.

Catalog:

```yaml
email:
  required: true

  sender:
    mode: platform-managed
```

Installation:

```text
Gitea
 |
 +-- mail identity:
     notifications@git.example.com
```

The platform creates the mail identity.

---

# 45. Application SMTP credentials

Each application gets unique credentials.

Never use a shared:

```text
smtp@example.com
```

credential across applications.

Example:

```text
Gitea:
    gitea-notifications@example.com

Nextcloud:
    nextcloud-notifications@example.com
```

This provides:

* attribution
* revocation
* compromise isolation
* auditability

---

# 46. Application sender policy

An application may only send using identities assigned to it.

Example:

```text
Gitea
  |
  +-- allowed sender:
      notifications@git.example.com
```

It must not be able to authenticate as:

```text
alice@example.com
```

unless explicitly granted.

---

# 47. Important chasquid sender restriction

Current chasquid behavior allows authenticated users to send using arbitrary sender addresses/domains by default. The chasquid documentation explicitly describes this as a design choice and recommends post-DATA hooks when stricter MAIL FROM/From validation is required.

Therefore the platform MUST implement an additional sender authorization layer.

Do not rely on chasquid's default authenticated-user behavior for application isolation.

---

# 48. Sender authorization hook

Use chasquid's `post-data` hook mechanism for sender policy enforcement.

chasquid exposes environment variables including:

```text
$MAIL_FROM
$RCPT_TO
$AUTH_AS
$ON_TLS
$FROM_LOCAL_DOMAIN
$SPF_PASS
$REMOTE_ADDR
```

which can be used by the hook to enforce policy.

The platform-generated hook should enforce:

```text
AUTH_AS
    |
    v
allowed sender identities
    |
    +-- permitted -> accept
    |
    +-- forbidden -> reject
```

---

# 49. Sender authorization data

Maintain:

```text
MailSubmissionAuthorization
---------------------------
id
mail_identity_id
credential_id
allowed_from_addresses[]
allowed_from_domains[]
application_instance_id
```

Example:

```text
Credential:
    app-gitea-abc

Authenticated as:
    gitea-notifications@example.com

Allowed MAIL FROM:
    gitea-notifications@example.com
```

---

# 50. User SMTP submission

A human user's chasquid credentials may be allowed to send from:

```text
alice@example.com
```

and optionally:

```text
aliases owned by Alice
```

but not automatically from:

```text
bob@example.com
```

unless explicitly delegated.

---

# 51. Mail delegation

Future model:

```text
MailSendPermission
------------------
grantor
grantee
sender_identity
```

Example:

```text
Alice
  grants
Gitea application
  permission to send as
notifications@example.com
```

Do not implement arbitrary delegation in v0 unless needed.

The initial implementation should use explicit ownership.

---

# 52. Mail certificates

chasquid supports multiple TLS certificates and integrates naturally with certificate provisioning. Its documented certificate directory structure is compatible with Let's Encrypt-style layouts.

The platform should expose:

```text
Mail TLS endpoint
```

separately from HTTP TLS.

Do not route SMTP through Traefik's HTTP authentication stack.

---

# 53. SMTP endpoints

Initial chasquid deployment should expose:

```text
25   SMTP
587  SMTP submission
```

Port 465 may be added if required by the deployment model.

SMTP traffic is directly handled by chasquid.

Traefik is not involved in normal SMTP handling.

---

# 54. Mail data plane

The architecture is:

```text
                       chasquid
                          |
        +-----------------+------------------+
        |                 |                  |
        v                 v                  v
     inbound          submission          outbound
       SMTP               SMTP              SMTP
        |                   |                  |
        v                   v                  |
     local/             users/apps             |
     future             |                     |
     service            v                     |
                    chasquid                  |
                                              |
                                   future external relay
```

The outbound path may initially be direct SMTP.

The platform must not hard-code that assumption.

---

# 55. Future inbound service

Future architecture:

```text
Internet
   |
   v
External inbound service
   |
   v
SMTP into chasquid
   |
   v
local mail / aliases
```

The external inbound service should not require changes to the platform user model.

---

# 56. Future outbound service

Future architecture:

```text
Applications/users
       |
       v
chasquid
       |
       v
External outbound relay
       |
       v
Internet
```

The platform should configure chasquid's outbound path through a provider abstraction.

---

# 57. MailProvider abstraction

The abstraction should now represent chasquid plus optional external transport.

```go
type MailProvider interface {
    EnsureDomain(ctx context.Context, domain MailDomain) error
    RemoveDomain(ctx context.Context, domainID string) error

    EnsureMailbox(ctx context.Context, mailbox Mailbox) error
    DisableMailbox(ctx context.Context, mailboxID string) error
    RemoveMailbox(ctx context.Context, mailboxID string) error

    EnsureAlias(ctx context.Context, alias MailAlias) error
    RemoveAlias(ctx context.Context, aliasID string) error

    EnsureSubmissionCredential(
        ctx context.Context,
        identity MailIdentity,
    ) (MailCredential, error)

    RevokeSubmissionCredential(
        ctx context.Context,
        credentialID string,
    ) error

    EnsureSenderPolicy(
        ctx context.Context,
        policy SenderPolicy,
    ) error

    GetDomainStatus(
        ctx context.Context,
        domainID string,
    ) (MailDomainStatus, error)
}
```

Initial implementation:

```text
MailProvider = ChasquidProvider
```

---

# 58. ChasquidProvider

Implement:

```go
type ChasquidProvider struct {
    ConfigDir string
    Control   ChasquidController
}
```

The provider must encapsulate:

* domain directory management
* user creation
* password rotation
* alias management
* DKIM management
* configuration reload/restart
* status checks
* sender policy generation

No other platform component should invoke `chasquid-util` directly.

---

# 59. Chasquid controller

Provide a narrow internal interface:

```go
type ChasquidController interface {
    AddUser(ctx context.Context, address string, password Secret) error
    RemoveUser(ctx context.Context, address string) error
    ChangePassword(ctx context.Context, address string, password Secret) error

    EnsureDomain(ctx context.Context, domain string) error
    RemoveDomain(ctx context.Context, domain string) error

    EnsureAlias(ctx context.Context, domain, localPart string, destinations []string) error
    RemoveAlias(ctx context.Context, domain, localPart string) error

    Reload(ctx context.Context) error
    Status(ctx context.Context) (ChasquidStatus, error)
}
```

This interface allows later replacement with:

* remote chasquid
* API wrapper
* sidecar
* another MTA

without changing the platform model.

---

# 60. Chasquid configuration ownership

The platform owns:

```text
/etc/chasquid/chasquid.conf
/etc/chasquid/domains/<domain>/users
/etc/chasquid/domains/<domain>/aliases
```

unless an explicit external-management mode is enabled.

Do not allow users to edit these files directly.

---

# 61. Configuration reconciliation

The platform should maintain desired mail state in PostgreSQL.

Example:

```text
Platform DB:

alice@example.com
bob@example.com

support@example.com
 -> alice@example.com
 -> bob@example.com
```

Reconciler compares that against chasquid.

```text
desired mail state
       |
       v
ChasquidProvider
       |
       v
chasquid
```

---

# 62. Password handling

Do not store plaintext chasquid passwords in the normal database.

Preferred:

```text
credential generated
       |
       v
secret store
       |
       v
chasquid user database
```

The platform stores only:

```text
credential_id
credential_hash/fingerprint
status
created_at
rotated_at
```

If chasquid's native user database requires a password hash, let chasquid generate/manage it through supported tooling.

---

# 63. Mail identity deletion

Deleting:

```text
alice@example.com
```

must NOT delete:

```text
platform user Alice
```

Likewise deleting a platform user must not silently delete mail data.

Default behavior:

```text
disable identity
retain mailbox/data
```

Permanent deletion requires explicit confirmation.

---

# 64. Domain deletion

A domain cannot be deleted while it has active:

* application hostnames
* mail identities
* aliases
* mail-enabled applications

The UI must show dependencies.

Example:

```text
Cannot delete example.com.

Applications:
  cloud.example.com
  git.example.com

Mail:
  alice@example.com
  support@example.com

Resolve these resources first.
```

---

# 65. Mail status

Expose:

```text
Mail domain:
    active

Chasquid:
    healthy

TLS:
    healthy

DKIM:
    configured

Inbound:
    not configured

Outbound:
    direct

Submission:
    healthy
```

Future external providers can populate:

```text
inbound:
    healthy

outbound:
    healthy
```

---

# 66. Mail health checks

The platform worker should verify:

* chasquid process health
* SMTP port 25
* SMTP submission port
* TLS certificate
* domain configuration
* local mailbox existence
* alias resolution
* DKIM configuration
* outbound connectivity
* future inbound connector
* future outbound connector

---

# 67. Mail observability

Export:

```text
mail_domains_total
mail_identities_total
mail_aliases_total

chasquid_health
chasquid_queue_size

mail_submission_success_total
mail_submission_failure_total

mail_reconciliation_success_total
mail_reconciliation_failure_total
```

Chasquid itself provides monitoring/HTTP status functionality and tracing facilities; integrate these into the platform's operational status where practical.

---

# 68. Mail audit events

Record:

```text
mail.domain.enabled
mail.domain.disabled

mail.identity.created
mail.identity.disabled
mail.identity.deleted
mail.identity.credential_rotated

mail.alias.created
mail.alias.updated
mail.alias.deleted

mail.sender_policy.created
mail.sender_policy.updated

mail.dkim.created
mail.dkim.rotated
```

Do not log:

* SMTP passwords
* message contents
* authentication secrets

---

# 69. Privacy boundary

The platform controls mail metadata but should not unnecessarily store message content.

Do not copy email bodies into the platform database.

Chasquid/mail storage remains the mail data plane.

The platform should expose only operational metadata unless a future mail UI explicitly requires message access.

---

# 70. Application catalog email schema

Example:

```yaml
email:
  required: true

  sender:
    mode: platform-managed
    local_part: notifications

  smtp:
    required: true
```

Installation creates:

```text
notifications@example.com
```

and an application-specific SMTP credential.

---

# 71. Application-specific sender naming

Prefer deterministic but collision-safe names:

```text
notifications-<instance-short-id>@example.com
```

or:

```text
<app>-notifications@example.com
```

The platform must sanitize application names.

Users may override the local part if available.

---

# 72. Mail domain ownership and application ownership

An application may only request a mail identity under a domain owned by the same organization.

Example:

```text
Organization A
 |
 +-- example.com
 |
 +-- Gitea
       |
       +-- notifications@example.com
```

Forbidden:

```text
Organization A
 |
 +-- Gitea
       |
       +-- notifications@example.org
```

unless `example.org` is also owned by Organization A.

---

# 73. SMTP credentials and application lifecycle

When an application is deleted:

1. Stop application.
2. Revoke its SMTP credential.
3. Disable its mail identity.
4. Preserve identity metadata for audit.
5. Optionally delete identity after retention policy.
6. Remove chasquid authorization.
7. Preserve or remove mailbox according to explicit deletion policy.

The credential must cease working immediately or as close to immediately as possible.

---

# 74. SMTP security

The platform must never provision authenticated SMTP over plaintext.

chasquid itself refuses authentication over plaintext and supports TLS-based authenticated submission.

The platform's generated application configuration must therefore use:

```text
TLS required
```

and reject insecure SMTP configuration.

---

# 75. Mail trust/security integration

The mail provider interface should expose future transport/trust status without exposing implementation details:

```go
type MailSecurityStatus struct {
    TLSReady       bool
    DKIMReady      bool
    SPFReady       bool
    DMARCReady     bool
    InboundReady   bool
    OutboundReady  bool
}
```

Initially:

```text
InboundReady  = false/not configured
OutboundReady = direct or configured implementation
```

Later the external services can populate these fields.

---

# 76. Future external transport interfaces

Do not overload `MailProvider` indefinitely.

Eventually split:

```go
type MailMTA interface {
    ...
}

type InboundMailProvider interface {
    ...
}

type OutboundMailProvider interface {
    ...
}
```

Initial implementation:

```text
MailMTA = Chasquid
InboundMailProvider = None
OutboundMailProvider = DirectSMTP
```

Future:

```text
MailMTA = Chasquid
InboundMailProvider = ExternalInbound
OutboundMailProvider = ExternalOutbound
```

This is the preferred long-term architecture.

---

# 77. Revised overall architecture

```text
                           INTERNET
                              |
             +----------------+----------------+
             |                                 |
        HTTP/HTTPS                           SMTP
             |                                 |
        +----v----+                       +----v-----+
        | Traefik |                       | Chasquid |
        +----+----+                       +----+-----+
             |                                 |
     +-------+-------+                 +-------+-------+
     |               |                 |       |       |
     v               v                 v       v       v
 Applications     authentik         users   aliases  queue
     |               |
     |               |
     +-------+-------+
             |
             v
       Platform API
             |
   +---------+----------+
   |         |          |
   v         v          v
 Domains   Users      Groups
   |         |          |
   +---------+----------+
             |
       PostgreSQL
             |
             v
        Reconciler
             |
   +----+----+----+----+
   |    |    |    |    |
   v    v    v    v    v
 DNS  Auth  Mail Docker Traefik
```

---

# 78. The critical unified identity relationship

The following must be possible:

```text
Alice
 |
 +-- Organization membership
 |
 +-- authentik identity
 |
 +-- groups
 |     |
 |     +-- admins
 |     +-- developers
 |
 +-- web applications
 |     |
 |     +-- cloud.example.com
 |     +-- git.example.com
 |
 +-- mail identities
       |
       +-- alice@example.com
       +-- alice@example.net
```

One platform identity.

Multiple capabilities.

---

# 79. Example: adding a new user

Administrator:

```text
Add Bob
```

Platform:

```text
1. Create platform User
2. Create authentik identity
3. Add Bob to organization
4. Add Bob to selected groups
5. Do NOT automatically create mailboxes
```

If the administrator selects:

```text
Create mailbox:
bob@example.com
```

then:

```text
6. Create MailIdentity
7. Provision chasquid user
8. Generate SMTP credential
9. Store secret
10. Show mail setup to Bob
```

---

# 80. Example: removing a user

Administrator removes Bob.

Platform:

```text
1. Disable platform user
2. Disable authentik identity
3. Remove organization memberships
4. Remove application access
5. Disable mail identities
6. Revoke SMTP credentials
7. Preserve mail data
8. Reconcile aliases
```

The platform should not destroy Bob's mailbox by default.

---

# 81. Example: adding a domain

User adds:

```text
example.com
```

Platform:

```text
1. Create Domain
2. Generate verification token
3. Verify ownership
4. Enable web
5. Enable mail
```

Mail provisioning:

```text
6. Create chasquid domain
7. Generate DKIM key
8. Configure TLS
9. Prepare MX/SPF/DKIM/DMARC requirements
10. Wait for verification
```

Web provisioning:

```text
11. Domain available for hostnames
12. Traefik can issue certificates
```

---

# 82. Example: install Nextcloud

User chooses:

```text
Nextcloud
cloud.example.com
organization members
```

Platform creates:

```text
DNS:
    cloud.example.com

TLS:
    cloud.example.com

OIDC:
    authentik client

Docker:
    Nextcloud
    PostgreSQL

Mail:
    nextcloud-notifications@example.com

SMTP:
    unique application credential

Authorization:
    organization members
```

No manual configuration is required.

---

# 83. Example: install an application without OIDC

User chooses:

```text
LegacyApp
legacy.example.com
```

Catalog declares:

```yaml
authentication:
  mode: forward-auth
```

Platform creates:

```text
Traefik router
authentik forward-auth provider
authorization bindings
application
```

Flow:

```text
Browser
   |
   v
Traefik
   |
   +--> authentik
   |
   v
LegacyApp
```

---

# 84. Example: group-driven email

Organization has:

```text
developers:
    Alice
    Bob
    Carol
```

Administrator creates:

```text
developers@example.com
```

The platform configures the chasquid alias:

```text
developers:
    alice@example.com
    bob@example.com
    carol@example.com
```

Bob leaves the developers group.

The reconciler automatically changes the alias.

---

# 85. Revised database tables

Minimum tables:

```text
organizations
users
organization_memberships

groups
group_memberships

domains
domain_verifications

dns_providers
dns_records

catalog_applications
catalog_versions

application_instances
application_hostnames

application_access_policies
application_access_groups

deployments
deployment_events

external_resources

secrets

mail_domains
mail_identities
mail_credentials
mail_aliases
mail_submission_policies

audit_events
```

---

# 86. Mail-specific constraints

Enforce:

```text
(domain_id, local_part) UNIQUE
```

for mail identities.

Aliases:

```text
(domain_id, local_part) UNIQUE
```

An address cannot simultaneously be:

```text
mailbox
```

and:

```text
alias
```

unless the platform explicitly supports alias-plus-mailbox semantics.

Default:

```text
one address = one primary mail object
```

---

# 87. Revised API

Add:

```text
POST   /api/v1/domains/:id/mail
GET    /api/v1/domains/:id/mail
DELETE /api/v1/domains/:id/mail

POST   /api/v1/domains/:id/mail-identities
GET    /api/v1/domains/:id/mail-identities

GET    /api/v1/mail-identities/:id
PATCH  /api/v1/mail-identities/:id
DELETE /api/v1/mail-identities/:id

POST   /api/v1/mail-identities/:id/credentials
POST   /api/v1/mail-identities/:id/credentials/rotate

POST   /api/v1/domains/:id/mail/aliases
GET    /api/v1/domains/:id/mail/aliases

GET    /api/v1/domains/:id/mail/status
```

---

# 88. Revised provider implementations

```text
IdentityProvider
    = Authentik

DeploymentProvider
    = DockerCompose

IngressProvider
    = Traefik

DNSProvider
    = Manual
    = Cloudflare

MailMTA
    = Chasquid

InboundMailProvider
    = None (v0)

OutboundMailProvider
    = DirectSMTP (v0)
```

Do not implement external mail providers yet.

---

# 89. Chasquid deployment

Run chasquid as a dedicated Compose service.

Recommended conceptual layout:

```yaml
services:
  chasquid:
    image: <pinned-chasquid-version>
    volumes:
      - chasquid-config:/etc/chasquid
      - chasquid-data:/var/lib/chasquid
      - certificates:/etc/chasquid/certs:ro
    ports:
      - "25:25"
      - "587:587"
```

The exact image/runtime configuration should be determined from the pinned chasquid release and tested before production use.

Do not use `latest`.

Current chasquid documentation lists 1.17.0 as a released version and documents Docker image improvements in that release.

---

# 90. Chasquid configuration generation

The platform should generate:

```text
chasquid.conf
```

for platform-controlled settings.

Domain-specific state should be generated through the ChasquidProvider.

Do not rewrite the entire configuration on every reconciliation if a targeted update is possible.

---

# 91. Chasquid restart/reload

Changes that require restart/reload must be coordinated.

Example:

```text
create domain
    |
    v
write desired state
    |
    v
validate config
    |
    v
reload/restart chasquid
    |
    v
health check
```

If configuration validation fails, preserve the previous working configuration.

Never leave chasquid in a partially written configuration state.

---

# 92. Mail reconciliation safety

Mail reconciliation must be conservative.

A failed reconciliation must not:

* delete all mail users
* remove all aliases
* replace the entire domain configuration
* invalidate all credentials

Only reconcile resources explicitly owned by the platform.

---

# 93. Chasquid backups

Back up:

```text
/var/lib/chasquid
/etc/chasquid
```

as application infrastructure data.

At minimum, preserve:

* queue
* domain configuration
* user databases
* aliases
* DKIM private keys
* TLS references/configuration

The platform database alone is not sufficient to restore the mail plane.

---

# 94. Disaster recovery

The platform must eventually support coordinated restore:

```text
PostgreSQL
     +
Chasquid data
     +
Chasquid configuration
     +
TLS/DKIM secrets
     +
application persistent data
```

Restoring PostgreSQL without chasquid data must be considered an incomplete restore.

---

# 95. Mail migration/import

Future functionality may support:

```text
Import existing domain
Import existing mailbox
Import aliases
```

Do not implement in v0.

The platform should nevertheless avoid assumptions that every chasquid mailbox was created by the platform.

An explicit:

```text
externally_managed
```

state may be introduced later.

---

# 96. v0 scope additions

Add:

```text
[ ] Chasquid Compose service
[ ] ChasquidProvider
[ ] mail domains
[ ] mail identities
[ ] mail credentials
[ ] mail aliases
[ ] group-driven aliases
[ ] application mail identities
[ ] application-specific SMTP credentials
[ ] sender authorization policy
[ ] chasquid post-DATA policy hook
[ ] DKIM provisioning
[ ] mail TLS
[ ] mail health checks
[ ] mail audit events
[ ] mail reconciliation
```

Explicitly do not implement:

```text
[ ] external inbound service
[ ] external outbound service
[ ] external spam service
[ ] external mailbox service
```

---

# 97. End-to-end acceptance test

A clean host must be able to execute:

```text
Create Organization
        |
        v
Create Alice
        |
        v
Create example.com
        |
        v
Verify example.com
        |
        v
Enable Mail
        |
        +--> chasquid domain created
        +--> DKIM configured
        +--> TLS configured
        |
        v
Create alice@example.com
        |
        +--> chasquid user created
        +--> SMTP credential created
        |
        v
Create support@example.com
        |
        +--> alias -> Alice
        |
        v
Install OIDC application
        |
        +--> cloud.example.com
        +--> authentik client
        +--> Traefik route
        +--> SMTP identity
        +--> application SMTP credential
        |
        v
Login
        |
        v
Application access granted
        |
        v
Send application email
        |
        v
chasquid accepts authenticated submission
        |
        v
sender policy validates identity
        |
        v
chasquid queues/delivers
```

---

# 98. Final architectural invariant

The platform must provide one coherent identity model:

```text
                       USER
                        |
             +----------+----------+
             |                     |
             v                     v
         authentik             MailIdentity
             |                     |
             v                     v
       Web applications        chasquid
             |                     |
             +----------+----------+
                        |
                        v
                   ORGANIZATION
                        |
                        v
                     DOMAIN
```

The user should never have to separately manage:

* a web identity
* an application identity
* a mail identity
* a domain identity

The platform manages their relationships.

---

# 99. Final desired user experience

A user should be able to perform:

```text
Add domain:
    example.com

Create user:
    Alice

Create mailbox:
    alice@example.com

Create alias:
    support@example.com -> Alice

Install:
    Nextcloud

Hostname:
    cloud.example.com

Access:
    Alice

Email:
    enabled
```

and the platform automatically produces:

```text
                    example.com
                         |
          +--------------+--------------+
          |              |              |
          v              v              v
       Web DNS          Mail          Identity
          |              |              |
          v              v              v
      Traefik         chasquid       authentik
          |              |              |
          v              v              v
    cloud.example   alice@example   Alice
```

No manual editing of:

* Compose files
* Traefik configuration
* authentik configuration
* chasquid domain files
* chasquid user files
* chasquid alias files
* SMTP credentials

should be necessary for normal operation.

---

# 100. Implementation order

## Phase 1 — Foundation

```text
1. PostgreSQL schema
2. Go domain model
3. REST API
4. migrations
5. OIDC platform login
6. audit logging
```

## Phase 2 — Identity

```text
7. authentik integration
8. users
9. organizations
10. memberships
11. groups
12. application authorization
```

## Phase 3 — Domains

```text
13. domain model
14. DNS verification
15. hostname model
16. domain authorization
```

## Phase 4 — Chasquid

```text
17. Chasquid Compose deployment
18. ChasquidProvider
19. mail domain provisioning
20. mail identity provisioning
21. SMTP credentials
22. aliases
23. DKIM
24. TLS
25. sender authorization
26. mail health
27. mail reconciliation
```

## Phase 5 — Applications

```text
28. catalog manifest
29. manifest validator
30. Docker Compose renderer
31. Docker deployment provider
32. Traefik route generation
33. native OIDC provisioning
34. forward-auth provisioning
35. application SMTP provisioning
```

## Phase 6 — Reconciliation

```text
36. external resource tracking
37. desired/observed state
38. reconciliation worker
39. retries
40. failure recovery
```

## Phase 7 — UI

```text
41. organizations
42. users
43. domains
44. mail
45. catalog
46. application deployment
47. status
48. audit
```

---

# 101. Definition of done

v0 is complete when:

```text
Fresh host
    |
    v
docker compose up
    |
    +-- platform
    +-- postgres
    +-- authentik
    +-- traefik
    +-- chasquid
    |
    v
Bootstrap admin
    |
    v
Create organization
    |
    v
Add/verify domain
    |
    v
Enable mail
    |
    +-- chasquid domain
    +-- DKIM
    +-- TLS
    |
    v
Create user
    |
    +-- authentik identity
    |
    v
Create mailbox
    |
    +-- chasquid user
    +-- SMTP credential
    |
    v
Create alias
    |
    +-- chasquid alias
    |
    v
Install application
    |
    +-- DNS
    +-- TLS
    +-- OIDC
    +-- Docker
    +-- SMTP identity
    +-- sender policy
    |
    v
Authenticated application
    |
    v
Application sends mail
    |
    v
chasquid accepts and processes message
```

The complete lifecycle must be reproducible entirely through the platform API/UI.

The platform database remains the source of truth for the relationship between:

```text
users
organizations
domains
applications
mail identities
mail aliases
permissions
```

chasquid remains the MTA/data plane.

Future external inbound/outbound services become transport adapters around chasquid and require no change to the fundamental user/domain/application model.


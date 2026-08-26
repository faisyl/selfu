# selfu

Self-hosted multi-domain application & mail platform: users sign in via
authentik (OIDC), the platform provisions mail identities on the chasquid MTA,
and apps ship through a declarative catalog rendered to Docker Compose.
PostgreSQL is the single source of truth; authentik, chasquid, and Traefik are
reconciled toward it. Stack: Go (`net/http`, no framework), PostgreSQL 17,
authentik, chasquid, Traefik, Redis — all pinned, orchestrated by Docker
Compose.

This document is the operator runbook for standing selfu up from zero and
onboarding domains and users. Developer guidelines live in `AGENTS.md`; the
authoritative technical spec is `spec.md`.

## Quick start: one-command bring-up

Prerequisites: a Linux host with Docker, Go 1.26+, and (for real DNS/TLS) a
domain you control plus a DNS provider token.

```bash
make bootstrap
```

`make bootstrap` runs `scripts/bootstrap.sh`, an **idempotent** chain (safe to
re-run; re-runs never rotate existing secrets):

1. `make doctor` — preflight checks: Docker daemon reachable, ports `:18080`
   and `:9000` free (ports held by existing selfu containers count as OK),
   DNS reachability, provider-token validity, disk space. Hard failures stop
   the run with actionable errors.
2. `.env` creation on first run only (copied from `.env.example`, secrets
   generated via `openssl rand`). Review `PLATFORM_HOST`, `AUTH_HOST`,
   `ACME_EMAIL`, `PUBLIC_IP` before exposing the host publicly.
3. `docker compose up -d --wait` — full 10-service stack (pinned tags).
4. Schema migrations (`migrate` service, goose).
5. `authentik-bootstrap` — idempotent OIDC provider/application boot.
6. Catalog seed (`seed` service) — registers the built-in application catalog
   (upsert on `(slug, version)`).
7. Prints a first-run summary:

```
Admin console : https://<PLATFORM_HOST>/ui/setup
Authentik     : https://<AUTH_HOST>
Bootstrap admin email:    <AUTHENTIK_BOOTSTRAP_EMAIL>
Bootstrap admin password: <AUTHENTIK_BOOTSTRAP_PASSWORD>
```

Keep the bootstrap admin password safe (it also lives in `.env`). Re-running
`make bootstrap` at any time converges without side effects.

## First-run wizard: `/ui/setup`

Open the admin console URL printed by bootstrap. An unonboarded install
redirects there automatically.

1. **Bootstrap login** — sign in with the bootstrap admin email/password
   (no manual OIDC pre-configuration needed). `GET /api/v1/setup` reports
   setup status, including background verification state.
2. **Primary-domain onboarding** — a single call creates the organization,
   owner membership, primary mail domain, and kicks off TXT verification
   (`POST /api/v1/setup`, authenticated).
3. **DNS provider** — choose how records are managed
   (`SELFU_ACCESS_PROVIDER`; per-install choice stored in the DB):
   - `cloudflare` — automatic: set `SELFU_CLOUDFLARE_API_TOKEN` /
     `SELFU_CLOUDFLARE_ZONE_ID`; the platform writes the verification TXT and
     origin A records itself.
   - `route53` — automatic via AWS Route 53 credentials.
   - `manual` — the wizard prints exact records to create by hand
     (`TXT <record> <value>`, origin A records).
4. **Verify** — `POST /api/v1/setup/verify` checks the TXT record. A
   background poller (`SELFU_VERIFY_POLL_INTERVAL`, default 15s) retries while
   setup is pending, so the wizard shows live status and completes on its own
   once DNS propagates. On success the install is marked onboarded.

## Onboarding users

Two paths, both driven from the admin console or REST API
(`internal/httpapi/router.go` is the route source of truth):

### Composite onboard-user (direct provisioning)

One authenticated call creates the user, org membership, mailbox (optional),
and returns the initial credential — idempotent, single audit trail:

```
POST /api/v1/organizations/{id}/onboard-user
{"email": "...", "display_name": "...", "role": "member",
 "group_id": "", "provision_mailbox": true, "local_part": "..."}
→ 200 {"user": {...}, "secret": "<one-time credential>", ...}
```

The secret is shown once; the admin hands it to the user out of band.

### Invite-first-login (no admin-handled secrets)

Preferred when the user can receive email:

1. Admin issues an invite (requires org admin role):
   ```
   POST /api/v1/organizations/{id}/invites
   {"email": "...", "display_name": "...", "role": "member"}
   → 200 {"user": {...}, "invite": {"token": "<one-time link token>",
          "expires_at": "...", ...}}
   ```
   The invite token is single-use, valid 7 days, and only its hash is stored;
   the response shows it exactly once. Re-inviting the same org/user pair
   expires the older pending invite.
2. The invitee redeems it and sets their own password (minimum 8 chars) —
   no administrator ever handles the credential:
   ```
   POST /api/v1/invites/accept   (unauthenticated)
   {"token": "...", "password": "..."}
   ```
   Membership lands atomically on redemption; replay or expiry is rejected.

## Day-2 operations

| Task | Command |
|---|---|
| Preflight checks | `make doctor` |
| Bring up / converge stack | `make bootstrap` (or `make up`) |
| Teardown | `make down` (add `-v` via `make clean` to wipe volumes) |
| Migration status | `make migrate-status` |
| Logs / ps | `make logs` / `make ps` |
| End-to-end acceptance | `./scripts/acceptance.sh` (against live stack) |
| Backups | `./scripts/backup.sh` (pg_dump + chasquid volume tarballs) |

Domains beyond the primary are added per-organization via
`POST /api/v1/organizations/{id}/domains` (+ `/verify`, mail enablement,
identities, aliases — see `router.go`). Mailboxes reconcile continuously:
the worker converges chasquid/authentik toward the database every
`SELFU_RECONCILE_INTERVAL` (default 30s) and never deletes external resources.

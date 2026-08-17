# selfu — Goal Tracker

Self-hosted multi-domain application platform (spec: `spec.md` v0.2 — **read-only**, never modified).

This file is the durable cross-session contract. It decomposes the v0.2 spec into
independently completable goals. Each session picks up the first `pending` goal (or
resumes an `in-progress` one), satisfies its success criteria, runs its verification,
updates this file, and commits.

## How to resume

1. Read this file. Pick the first goal with status `pending` (or the `in-progress` goal).
2. Read the goal's entry: dependencies, success criteria, verification commands, scope, stop conditions.
3. Implement; satisfy every success criterion (binary, verified, no judgment calls).
4. Run the goal's Verification commands; all must pass.
5. Update the Status table + per-goal notes; commit; report.
6. Never start a goal whose dependencies are not `done`.

## Status

| Goal | Spec phase | Status | Notes |
|---|---|---|---|
| G1 Foundation | 1 | done | verified 2026-08-17 (incl. auth.login.succeeded audit) |
| G2 Identity | 2 | done | verified 2026-08-17: add-user/remove-user + authentik sync + default-deny |
| G3 Domains | 3 | done | verified 2026-08-17: TXT verification, containment, verified hostname gate |
| G4 Mail (chasquid) | 4 | pending | depends on G3 |
| G5 Applications | 5 | pending | depends on G4 |
| G6 Reconciliation | 6 | pending | depends on G5 (worker exists from G1) |
| G7 UI | 7 | pending | depends on G6 |
| G8 Acceptance & hardening | v0 | pending | depends on G7 |

## Cross-cutting constraints (every goal)

- Platform DB (PostgreSQL) is the source of truth; authentik/chasquid/Traefik/Docker/DNS hold observed state (§21).
- Every operation must be idempotent (§21, §92).
- No `latest` tags; pin exact image and toolchain versions (§89).
- No manual editing of generated state: chasquid domain files, Traefik config, authentik config, compose files (§28, §60, §99).
- Secrets: never plaintext in DB or logs (§35, §62); unique credentials per entity, never shared (§45).
- External inbound/outbound mail transport is out of scope for v0 — no new abstractions for them beyond the specified seams (MailProvider/MailMTA split, §57/§76).
- Work only inside this repo; `spec.md` read-only.

---

## G1 — Phase 1 Foundation

**Status (2026-08-17):** **VERIFIED — G1 COMPLETE.** All success criteria met:
unit tests/vet/build green; migrations apply to fresh PG and are idempotent;
compose stack healthy; health 200; `/me` 401 unauthenticated; and an
interactive authentik login (done manually) produced a `users` row
(`admin@selfu.local`) and `auth.login.succeeded` audit events — both counts ≥ 1.

**Handoff:** G1 has no pending action; next goal is **G2 (Identity)**.

**Operating notes (learned this session, keep into later goals):**
- authentik 2026.5.6 (all-in-one image) binds HTTP on `:9000` and HTTPS on
  `:9443` **on IPv6 only**; compose must map `9000:9000`, NOT `9000:8080` (that
  port is not bound — connections reset). Used HTTP for this phase so no TLS/cert
  in the browser path.
- OAuth2 providers in authentik are created via `/api/v3/providers/oauth2/`
  (there is no `oidc` model); their `pk` is an integer while flows/certkeys/apps
  use UUID-string `pk`. Must set `grant_types:["authorization_code"]` and attach
  the default scope mappings (`email`,`profile`,`openid`) or authorize rejects.
  `redirect_uris` entries are objects `{url, matching_mode:"strict"}`; an
  `invalidation_flow` is required. All now baked into `cmd/authentik-bootstrap`.
- Host `:8080` was already occupied by an unrelated service → the platform runs
  on `:18080` (update `SELFU_HTTP_ADDR`/redirect/config if that conflicts).
- API uses `network_mode: host`; valid only until Phase 5 (Traefik) replaces it.
- Docker group access granted (`usermod -aG docker faisal`); use `sg docker -c …`.

**Objective.** Bootstrappable Go project: PostgreSQL schema + migrations, Go domain model, REST API, authentik OIDC platform login, audit logging — wired into a pinned Docker Compose stack (postgres, authentik, api).

**Success criteria (all binary)**
1. `go build ./...`, `go vet ./...`, `go test ./...` exit 0; unit tests cover domain model + audit logging.
2. Migrations apply to fresh PostgreSQL and re-apply as no-op (idempotent); `audit_events` + Phase-1 tables exist.
3. `docker compose up -d --wait` brings up postgres + authentik + api; `GET /api/v1/health` → 200; protected route → 401 unauthenticated.
4. OIDC login end-to-end: browser via authentik → platform session → `GET /api/v1/me` returns user; `users` ≥ 1 row and `audit_events` ≥ 1 row.
5. No `latest` tags in committed manifests; toolchain pinned.

**Verification**
- `go vet ./... && go test ./... && go build ./...`
- `docker compose up -d --wait postgres`; migrate twice (second = no-op); psql check for tables.
- `docker compose up -d --wait`; `curl -fsS http://localhost:8080/api/v1/health`; 401 check on protected route.
- Browser tool: authentik login; confirm `/api/v1/me`; psql `users`/`audit_events` counts ≥ 1.

**Scope in**: repo bootstrap, Go module, migrations framework, audit event persistence + middleware, domain model (User, AuditEvent), API with auth middleware + `/me`, OIDC integration, compose stack.

**Scope out**: orgs/memberships/groups CRUD, authentik admin-API provisioning, domains, mail, apps, UI, reconciler → G2–G7.

**Stop**: env blocker (no Docker daemon, unpullable images, Go install fail); 3 failed fix cycles on one verification without root cause; product ambiguity (OIDC claim mapping, bootstrap admin, secret storage); budget exhausted (pause, resume later).

**Dependencies**: none.

---

## G2 — Identity (Phase 2)

**Status (2026-08-17): VERIFIED — G2 COMPLETE** (`9a544e0`). All criteria held
live: org/membership/group/user CRUD with owner>admin>member + default-deny
(non-admin 403); platform user→authentik user (pk int) and platform group→
authentik group (pk uuid) provisioned with external ids in `external_resources`;
add-user workflow created user + authentik identity + membership + no mailbox;
remove-user workflow set platform status=disabled, stripped org+group
memberships, disabled the authentik identity (`is_active=False`), and retained
the user row. Migration 00002 idempotent; full go gate green.

**Objective**: authentik integration (admin API), users, organizations, memberships, groups, application authorization model (§4, §15–17, §79–80).

**Success criteria**
1. Users/orgs/memberships/groups CRUD via API; permissions: owner > admin > member; authorization default-deny foundation.
2. authentik users/groups/applications created for platform objects; external IDs stored per §16 (never inferred from names); verify via authentik admin API.
3. Add-user workflow (§79): platform + authentik + memberships + groups; no automatic mailbox creation.
4. Remove-user workflow (§80): disable authentik identity, strip memberships/access; preserve data.
5. Unit + integration tests for flows; same build/vet/test gate as G1.

**Verification**: standard Go gate; integration script against running compose stack (authentik admin API assertions); psql row checks.

**Dependencies**: G1.

---

## G3 — Domains (Phase 3)

**Status (2026-08-17): VERIFIED — G3 COMPLETE** (`62f4a39`, `181c451`). Domain
create (IDNA/`Example.COM`→`example.com`, pending + crypto token), verification
instructions returned (Manual provider, automated=false); real-DNS verify gate
(422 lookup); hostname binding refused until verified (409) and only within the
domain (unit-tested look-alike rejections); positive path (verify→bind→delete
dependents 409) covered by handler test; migration 00003 idempotent (v3).
Cloudflare provider implemented behind the abstraction (not live-verified — no
API token here); G6 owns record reconciliation.

**Objective**: domain model, DNS TXT verification (§10–§11), hostname model with proper containment (no naive suffix checks, §12), domain authorization, DNS provider abstraction (Manual + Cloudflare, §88).

**Success criteria**
- Domain lifecycle pending → verification_required → verified → suspended; verified gates hostnames/mail.
- TXT token `_platform-verification.<domain>` checked by provider; state flips only on real record presence.
- Hostname containment: label-boundary + IDNA-correct check; unit tests with look-alike/suffix cases.
- DNS records provisioned & tracked (G6 later); Manual provider emits instructions; Cloudflare via API.
- Domain can't be deleted with active dependents (§64).

**Dependencies**: G2.

---

## G4 — Mail (Phase 4, chasquid)

**Objective**: chasquid compose service; ChasquidProvider + ChasquidController (§58–59); mail domains/identities/credentials/aliases; DKIM, TLS, sender authorization + post-DATA hook (§47–50); health + reconciliation (§66); mail audit events (§68).

**Constraints from spec**: native chasquid structures (§28–29); `chasquid-util` only via provider; independent SMTP credentials, never reused (§35, §45); one address = one primary mail object (§86); no cross-org routing by default (§39); no catch-all by default (§40); deletion preserves mailboxes (§63); conservative reconciliation (§92); config integrity with validation before reload (§91).

**Dependencies**: Phase 3 (domains verified before mail).

---

## G5 — Applications (Phase 5)

**Objective**: declarative catalog (§13, no arbitrary compose/traefik fragments — §18), manifest validator, compose renderer, docker: Compose deployment provider (isolated per-instance projects, §20), Traefik route generation, authentik OIDC provider + forward-auth (§83), app SMTP identity + unique credential + sender policy (§44–46, §70–73).

**Dependencies**: Phase 4 (mail), phases… authentik (Phase 2), domains (Phase 3).

---

## G6 — Reconciliation (Phase 6)

**Objective**: ExternalResource tracking (§22), desired vs observed state §21, worker loop, retries, failure recovery, idempotency guarantee, conservative failure mode (§92).

**Dependencies**: all provisioning surfaces exist (G2–G5).

---

## G7 — UI (Phase 7)

**Objective**: admin console for orgs, users, domains, mail, catalog, deployment, status, audit; thin client over API; no separate auth (platform OIDC session, §15).

**Dependencies**: G6 (or streaming marks as acceptable: G5; see session decision).

---

## G8 — Acceptance & hardening (v0)

**Objective**: clean-host end-to-end (§97, §101) reproducible through API/UI only; runbook; backups for chasquid + postgres volumes (§93); DR restore design (§94); version-pin audit; security review.

**Dependencies**: G7 (or G5 for API-only acceptance — see remark in G7).

---

<!-- DO NOT EDIT this line? — keep single source of truth. -->
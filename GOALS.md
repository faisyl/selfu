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
| G1 Foundation | 1 | in-progress | 2026-08-16: started; repo bootstrap, schema, API, OIDC login, audit |
| G2 Identity | 2 | pending | depends on G1 |
| G3 Domains | 3 | pending | depends on G2 |
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
# Repository Guidelines

**selfu** — self-hosted multi-domain application & mail platform (Go, PostgreSQL, Docker Compose).

The authoritative sources are `spec.md` (v0.2 technical spec, **read-only — never modify**) and `GOALS.md` (durable session contract, phased goals G1–G9, all currently done, verified 2026-08-18). Follow `GOALS.md`'s resume procedure after any session boundary: pick the first pending goal, satisfy binary criteria, run verification, update the table, commit. The operator runbook (first-run bootstrap → wizard → user onboarding → invites) lives in `README.md`.

## Project Overview

Self-hosted platform that owns identity/tenancy and deploys applications next to mail: users sign in via authentik (OIDC), platform provisions mail identities on the chasquid MTA, and apps ship through a declarative catalog rendered to Docker Compose. PostgreSQL is the **single source of truth** for platform state; authentik, chasquid, and Traefik hold only observed state and are reconciled toward the DB.

Stack: Go (`net/http`, no web framework), PostgreSQL 17 (two DBs on one instance: `selfu` + `authentik`), authentik 2026.5.6 (IdP), chasquid 1.17.0 (MTA), Traefik 3.7 (ingress), Redis 7.4. Production images are pinned — **no `latest` tags** (§89).

## Architecture & Data Flow

```
cmd/api (HTTP)──> httpapi.Deps ──> store interfaces ──> PostgreSQL
cmd/worker ──> store.Recon ──> recon.MailReconciler ──> chasquid.AgentClient (chasquid sidecar)
                            └─> recon.SyncExternal ──> authentik admin API
cmd/authentik-bootstrap ──> authentik (idempotent OIDC provider/app boot)
```

- **Dependency direction**: `domain/` is a pure leaf (no I/O, framework-free). Every importable module depends on the narrow interfaces declared in `internal/store/interfaces.go` (`UserStore`, `AuditStore`, `IdentityStore`, `DomainStore`, `MailStore`, `AppStore`, `GroupStore`, `Recon`); the concrete `Store` is compile-time asserted against each (`_ UserStore = (*Store)(nil)`). `httpapi` is the only module that wires across all domains, receiving `httpapi.Deps` from `cmd/api/main.go`.
- **DI is fully manual**: constructors/structs assembled in `cmd/*`; no injection framework. Each seam interface has **two adapters**: the real store/client and a test fake — the fake must stay honest with the interface.
- **Request flow** — `router.go` assigns `X-Request-ID`, middleware recovers panics, `authn`/`requireOrgRole` default-deny (owner > admin > member), handler maps HTTP → store interface method → `domain` types → audit log.
- **Background loop** — `cmd/worker/main.go` ticks every `SELFU_RECONCILE_INTERVAL` (default 30s), reconciles each active mail domain, then `recon.SyncExternal`. Conservative: never deletes external resources, only converges observed→desired.
- **State** — DB is truth: idempotent `ON CONFLICT` upserts, `ExternalResource` rows track `desired_hash` vs `observed_hash` (sha256 of type:externalID). Migrations are **idempotent by contract** (applying twice = no-op, G1 acceptance).

## Key Modules

| Path | Purpose |
|---|---|
| `cmd/api/`, `cmd/worker/`, `cmd/migrate/`, `cmd/chasquid-agent/`, `cmd/authentik-bootstrap/`, `cmd/doctor/`, `cmd/seed/` | thin binaries; each `main()` |
| `internal/httpapi/` | REST API + server-rendered UI (`web/*.html`), `router.go` = route truth |
| `internal/store/` | only persistence owner; `interfaces.go` seams, `migrations/*.sql` (goose), `const ...SQL` query literals per file |
| `internal/domain/` | pure entities: `models.go` (User, AuditEvent), `mail.go`, `domains.go`, `identity.go` |
| `internal/auth/` | HMAC-signed stateless session cookies + OIDC client |
| `internal/authentik/` | authentik admin REST client (provisioning, `WaitReady`) |
| `internal/chasquid/` | `ChasquidController` interface + `AgentClient` HTTP wrapper into the sidecar; `Secret` redacted in logs |
| `internal/provision/` | 7-step mailbox provisioning pipeline (`Provisioner`, `Rotate`); credential fingerprint stored, never plaintext |
| `internal/recon/` | reconciliation worker logic |
| `internal/dns/`, `internal/access/` | DNS `Provider` (`ManualProvider` / `CloudflareProvider`) with `TXTLookup` verification; `access.Provider` composes DNS + ACME challenge per external-access provider (`manual` / `cloudflare` / `route53`), selected at setup |
| `internal/catalog/`, `internal/deploy/`, `internal/traefik/` | pure generators: strict YAML app catalog (unknown fields **rejected**), Compose renderer, Traefik route labels |
| `internal/config/` | `config.Load()` — env-only, validation, `SELFU_*` constants single source of truth |
| `internal/version/` | `version.Version` injected via ldflags |

## Development Commands

```bash
make build          # go build -ldflags "-X selfu/internal/version.Version=$(git describe ...)"
make test           # go test ./...
make vet            # go vet ./...
make fmt            # gofmt -w .

make up             # docker compose up -d --wait   (full stack)
make down / ps / logs
make gen-env        # copy .env from .env.example; regenerate ONLY secret fields (openssl rand)
make doctor         # preflight: docker, ports :18080/:9000, DNS, provider token (idempotent-safe)
make bootstrap      # one-command first run: doctor → gen-env → up --wait → migrate → authentik-bootstrap → seed → summary
make migrate-up     # go run ./cmd/migrate up
make migrate-status # go run ./cmd/migrate status
make clean          # docker compose down -v && go clean

./scripts/acceptance.sh   # end-to-end acceptance vs live compose stack (spec §97)
./scripts/dns-records.sh  # Cloudflare A records for PLATFORM_HOST/AUTH_HOST/MAIL_HOST
./scripts/backup.sh       # pg_dump -Fc selfu + authentik + chasquid volume tarballs -> backups/
```

- Go 1.26.6 (`go.mod`); direct deps: `jackc/pgx/v5`, `pressly/goose/v3`, `coreos/go-oidc/v3`, `google/uuid`, `golang.org/x/oauth2`, `gopkg.in/yaml.v3`. No test-only deps.
- **CI is nonexistent** — the project's CI is `go vet && go test && go build` run locally, plus `docker compose up -d --wait` smoke and `scripts/acceptance.sh` against the live stack.

## Code Conventions & Common Patterns

- **Naming**: `snake_case.go` files; `PascalCase` types; `SCREAMING_SNAKE` constants; enum values are string consts (`UserStatusActive = "active"`). Handlers: `<resource>_handlers.go` in `httpapi`.
- **Errors**: Go native — never exceptions. Module-level sentinels via `errors.New` (`store.ErrNotFound`/`ErrConflict`, `chasquid.ErrUnavailable`, `auth.ErrSessionInvalid`) checked with `errors.Is`; wrapped with `fmt.Errorf("...: %w")`. `pgx` unique violation (code `23505`) → `ErrConflict` via `store.isUnique`.
- **SQL**: `const ...SQL` string literals module-level, per-file (`upsertUserSQL`), executed via pgx `pool`.
- **Async**: goroutines + `select` on `signal.NotifyContext` (api), `time.Ticker` loop (worker); **all store calls take `ctx`** threaded from the request. No worker-pool framework.
- **Dependency injection**: manual struct fields / explicit args (`httpapi.Deps`, `provision.Provisioner(st, mta, m)`); two adapters per interface.
- **Logging**: `log/slog` JSON handler to stdout (`slog.NewJSONHandler(os.Stdout, nil)`); request correlation via `X-Request-ID`.
- **Security invariants (preserve always)**: secrets never plaintext (catalog/`chasquid.Secret` redact `String()`); fingerprint hashes for credentials; `subtle.ConstantTimeCompare`; OIDC nonce/state anti-CSRF; session cookie `HttpOnly`+`SameSite=Lax`; `sanitize()` any user-derived identifier before feeding Traefik/Compose labels; never commit `.env` (gitignored; `.env.example` is committed template).

## Important Files

- `spec.md` — authoritative spec; **`GOALS.md` — durable contract; read both before schema/behavior changes**
- `compose.yaml` — 10-service prod stack, pinned tags, `${VAR:?set}` env, YAML anchors for authentik
- `Dockerfile` — multi-stage: `golang:1.26.6` → 4 binaries (`api`, `migrate`, `authentik-bootstrap`, `worker`), distroless runtime
- `docker/chasquid.Dockerfile` — 4-stage MTA build (`chasquid v1.17.0` pinned + agent)
- `internal/store/migrations/` — ordered SQL migrations (goose), must stay idempotent
- `internal/httpapi/router.go` — single source of truth for REST surface
- `scripts/*.sh` — acceptance, bootstrap, DNS records, backup; `README.md` is the operational runbook built on these

## Runtime/Tooling Preferences

- **Language**: Go 1.26.6; **module path `selfu`** (`go.mod`, no external module prefix).
- **Runtime**: container-first via Docker Compose; dev against `docker compose up -d --wait` + local `Makefile` targets. Local run needs `.env` present: `cp .env.example .env && make gen-env` (edit `PUBLIC_IP`/hostnames after).
- **Env config**: all config via environment (`SELFU_*` / `AUTHENTIK_*` / `CLOUDFLARE_*` / `CHASQUID_*` — see `internal/config/`). Required: `SELFU_DATABASE_URL`, OIDC client, `SELFU_SESSION_SECRET` ≥ 32 bytes, `AUTHENTIK_URL/TOKEN`. No config files or CLI flags.
- **Known environment nits** (don't "fix" silently, they're live-checked): `migrate-up`/`migrate-status` work on a `go run ./cmd/migrate` target — inside the compose stack use the `migrate` service instead (`docker compose run --rm migrate up`, which is what `scripts/bootstrap.sh` does; the DB port is not published to the host).
- App-install provider (compose-'up' for catalog apps) is still open/deferred — the API container has **no Docker socket**; deployment currently renders Compose only.

## Testing & QA

- **Framework**: stdlib `testing` only — no testify, no TestMain, no external test-deps. Same-package `internal` tests. Patterns: table-driven loops (occasionally `t.Run` for compound models), hand-rolled `fake*` in-memory stubs (e.g. `fakeDomainStore`, `fakeMail`, `fakeOIDC`), black-box HTTP via `httptest.NewRequest`+`NewRecorder` through the real router, `t.Setenv` for config hermeticity, time injection via struct field (`s.now`) rather than clock globals.
- **Coverage**: none enforced — no coverage flags or thresholds anywhere. Goal is `go test ./...` green + `go vet ./...` clean.
- **No DB/Docker integration tests** in Go; the end-to-end surface is `scripts/acceptance.sh` (mints admin session from `SELFU_SESSION_SECRET`, curl `--resolve platform.pruxi.in→127.0.0.:` through real OIDC → org → domain verify → mail + identities + SMTP AUTH :587 + alias + reconcile + gitea app install + audit). Run it only against a live compose stack with a `.env` and a verified mail-ready domain (default `pruxi.in`); overridable via `SELFU_ACCEPTANCE_API` / `SELFU_ACCEPTANCE_DOMAIN`.
- **When adding a test**: keep it deterministic, isolated, full-suite-safe; prefer fakes that satisfy the narrow interface over mocking packages; assert behavior/boundaries/invariants, not implementation.
#!/usr/bin/env sh
# bootstrap.sh — one-command first-run setup for a selfu host (make bootstrap).
#
# Idempotent: every step is safe to re-run. Chain:
#   doctor -> gen-env (first run only) -> compose up --wait
#   -> migrate -> authentik-bootstrap -> catalog seed -> summary.
set -eu

say()  { printf '\n==> %s\n' "$1"; }
fail() { printf '\n!!  %s\n' "$1" >&2; exit 1; }

cd "$(dirname "$0")/.."

say "0/6 preflight (doctor)"
go run ./cmd/doctor || fail "doctor reported hard failures — fix them and re-run make bootstrap"

if [ ! -f .env ]; then
    say "1/6 creating .env from .env.example with generated secrets"
    cp .env.example .env
    make --no-print-directory gen-env >/dev/null
    echo "    .env created — review hosts (PLATFORM_HOST, AUTH_HOST, ACME_EMAIL, PUBLIC_IP) before exposing publicly."
else
    say "1/6 .env exists — keeping existing secrets (re-running never rotates them)"
fi
set -a; . ./.env; set +a

say "2/6 docker compose up -d --wait"
docker compose up -d --wait

say "3/6 schema migrations"
docker compose run --rm migrate up

say "4/6 authentik OIDC bootstrap"
docker compose run --rm authentik-bootstrap

say "5/6 application catalog seed"
docker compose run --rm seed

say "6/6 first-run summary"
PLATFORM_URL="https://${PLATFORM_HOST}"
echo "
  selfu is up.

  Admin console : ${PLATFORM_URL}/ui/setup
  Authentik     : https://${AUTH_HOST}

  Bootstrap admin email:     ${AUTHENTIK_BOOTSTRAP_EMAIL}
  Bootstrap admin password:  ${AUTHENTIK_BOOTSTRAP_PASSWORD}

  Keep the password safe (it lives in .env). Open the admin console URL to
  finish onboarding (DNS + TLS wizard). Re-running 'make bootstrap' is safe."

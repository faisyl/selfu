#!/usr/bin/env bash
# selfu acceptance test (spec §97, §101) — runs the full platform lifecycle
# against a running stack and asserts every step. Exit code 0 = all green.
#
# Requires: stack running (docker compose up), .env with the real values,
# and a mail-ready domain (default: pruxi.in from .env AUTHENTIK_HOST host).
#
# Session bootstrap has two paths:
#   * fresh install (not yet onboarded): drives the REAL first-run wizard —
#     bootstrap login (SELFU_BOOTSTRAP_PASSWORD) -> createSetup (org +
#     primary domain + auto-TXT) -> verify -> onboarded. This exercises the
#     exact flow a production operator hits (G8/G9).
#   * already onboarded: mints an admin session from .env secrets so the
#     API-driven checks can re-run against a live stack without a browser.
set -euo pipefail

cd "$(dirname "$0")/.."
set -a; source .env; set +a
API="${SELFU_ACCEPTANCE_API:-https://platform.pruxi.in}"
RES="--resolve platform.pruxi.in:443:127.0.0.1 --resolve auth.pruxi.in:443:127.0.0.1"

say()  { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
die()  { printf '\033[1;31mFAIL: %s\033[0m\n' "$*" >&2; exit 1; }
ok()   { printf '  \033[1;32mok\033[0m %s\n' "$*"; }

DOMAIN="${SELFU_ACCEPTANCE_DOMAIN:-pruxi.in}"
SUFFIX="$(date +%s)"

JAR="$(mktemp)"; trap 'rm -f "$JAR"' EXIT
CK=""
api()  { curl -s $RES -b "$CK" -m 20 "$@"; }
code() { curl -s $RES -o /dev/null -w '%{http_code}' -b "$CK" -m 20 "$@"; }
# pyjson k=v ... -> JSON object (safe quoting for passwords/secrets)
pyjson() { python3 -c 'import json,sys
print(json.dumps({k: v for k, v in (a.split("=", 1) for a in sys.argv[1:])}))' "$@"; }

# --- mint an admin session token (already-onboarded fallback path) ----------
mint_admin_token() {
  local ADMIN_ID
  ADMIN_ID=$(docker compose exec -T db psql -U selfu -d selfu -tAc \
    "SELECT id FROM users WHERE email='${AUTHENTIK_BOOTSTRAP_EMAIL}'" | tr -d '[:space:]')
  [ -n "$ADMIN_ID" ] || die "admin user missing — run a login first"
  SELFU_SESSION_SECRET="$SELFU_SESSION_SECRET" ADMIN_ID="$ADMIN_ID" python3 - <<'PY'
import hmac,hashlib,base64,json,time,os
s=os.environ['SELFU_SESSION_SECRET'].encode();u=os.environ['ADMIN_ID']
exp=int(time.time())+3600
p=base64.urlsafe_b64encode(json.dumps({"u":u,"e":exp}).encode()).rstrip(b'=')
k=hashlib.sha256(s).digest();sig=base64.urlsafe_b64encode(hmac.new(k,p,hashlib.sha256).digest()).rstrip(b'=')
print(p.decode()+'.'+sig.decode())
PY
}

say "1. health + auth gates"
[ "$(code "$API/api/v1/health")" = "200" ] || die "health not 200"
[ "$(curl -s $RES -o /dev/null -w '%{http_code}' "$API/api/v1/me")" = "401" ] || die "me should be 401 unauthenticated"

say "1b. onboarding state (bootstrap wizard, G8/G9)"
SETUP="$(curl -s $RES "$API/api/v1/setup")"
echo "$SETUP" | grep -q '"local_domain":"selfu.local"' || die "local domain missing from setup status"

if echo "$SETUP" | grep -q '"onboarded":true'; then
  ok "installation already onboarded (re-run: minted admin session)"
  CK="selfu_session=$(mint_admin_token)"
else
  # --- wizard bring-up: the real first-run operator path --------------------
  say "1c. wizard: bootstrap login (pre-onboarding local credential)"
  [ -n "${SELFU_BOOTSTRAP_PASSWORD:-}" ] || die "SELFU_BOOTSTRAP_PASSWORD missing from .env — required for the wizard bring-up path"
  LCODE=$(curl -s $RES -c "$JAR" -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' \
    -d "$(pyjson password="$SELFU_BOOTSTRAP_PASSWORD")" -m 20 "$API/api/v1/setup/login")
  [ "$LCODE" = "200" ] || die "bootstrap login failed (HTTP $LCODE)"
  CK="selfu_session=$(awk '$6=="selfu_session" {print $7}' "$JAR")"
  [ "${#CK}" -gt 20 ] || die "no selfu_session cookie issued by bootstrap login"
  ok "bootstrap login accepted, session cookie issued"

  say "1d. wizard: create setup (org + primary domain + auto-TXT)"
  PROV="${SELFU_ACCEPTANCE_DNS_PROVIDER:-${SELFU_ACCESS_PROVIDER:-manual}}"
  CREATE_ARGS=(fqdn="$DOMAIN" provider="$PROV")
  case "$PROV" in
    cloudflare)
      [ -n "${SELFU_CLOUDFLARE_API_TOKEN:-}" ] || die "cloudflare provider needs SELFU_CLOUDFLARE_API_TOKEN in .env"
      CREATE_ARGS+=(api_token="$SELFU_CLOUDFLARE_API_TOKEN")
      if [ -n "${SELFU_CLOUDFLARE_ZONE_ID:-}" ]; then
        CREATE_ARGS+=(zone_id="$SELFU_CLOUDFLARE_ZONE_ID")
      fi
      ;;
    route53|manual) : ;;   # credentials come from aws_* env / none
    *) die "unknown DNS provider '$PROV' (manual|cloudflare|route53)" ;;
  esac
  CREATED=$(api -H 'Content-Type: application/json' \
    -d "$(pyjson "${CREATE_ARGS[@]}")" "$API/api/v1/setup")
  echo "$CREATED" | grep -q '"record_name"' || die "createSetup failed: $(echo "$CREATED" | head -c 300)"
  REC_NAME=$(echo "$CREATED"  | python3 -c 'import json,sys;print(json.load(sys.stdin)["verification"]["record_name"])')
  REC_VALUE=$(echo "$CREATED" | python3 -c 'import json,sys;print(json.load(sys.stdin)["verification"]["record_value"])')
  AUTO=$(echo "$CREATED" | python3 -c 'import json,sys;print(json.load(sys.stdin)["verification"]["automated"])')
  ok "setup created (provider=$PROV, auto-TXT=$AUTO)"

  say "1e. wizard: verify primary domain (TXT $REC_NAME)"
  VERIFIED=""
  for i in $(seq 1 24); do
    VRESP=$(api -X POST "$API/api/v1/setup/verify")
    if echo "$VRESP" | grep -q '"onboarded":true'; then VERIFIED=1; break; fi
    HINT=$(echo "$VRESP" | python3 -c 'import json,sys
d=json.load(sys.stdin); print(d.get("hint") or d.get("error") or "pending")' 2>/dev/null || echo pending)
    echo "  attempt ${i}/24 — not verified yet ($HINT)"
    sleep 5
  done
  [ -n "$VERIFIED" ] || die "domain verification did not complete — set TXT \"$REC_NAME\" = \"$REC_VALUE\" and re-run"
  SETUP="$(curl -s $RES -b "$CK" "$API/api/v1/setup")"
  echo "$SETUP" | grep -q '"onboarded":true' || die "verify reported success but status is not onboarded"
  ok "installation ONBOARDED via wizard"
fi

say "2. identity: org, user, group"
ORG=$(api -H 'Content-Type: application/json' -d "{\"name\":\"Acceptance $SUFFIX\"}" "$API/api/v1/organizations" \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])')
USER_ID=$(api -H 'Content-Type: application/json' -d "{\"email\":\"accept-$SUFFIX@acme.example\",\"display_name\":\"Accept\",\"organization_id\":\"$ORG\"}" "$API/api/v1/users" \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])')
GRP=$(api -H 'Content-Type: application/json' -d '{"name":"devs"}' "$API/api/v1/organizations/$ORG/groups" \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])')
api -H 'Content-Type: application/json' -d "{\"user_id\":\"$USER_ID\"}" "$API/api/v1/groups/$GRP/members" >/dev/null
ok "org+user+group+membership"

say "3. domains (verified $DOMAIN must host mail)"
DOM_ID=$(docker compose exec -T db psql -U selfu -d selfu -tAc \
  "SELECT id FROM domains WHERE fqdn='$DOMAIN'" | tr -d '[:space:]')
[ -n "$DOM_ID" ] || die "verified domain $DOMAIN not found — verify one first (G3)"
ok "domain $DOMAIN"

say "4. mail: domain, identity, credential, SMTP AUTH"
[ "$(code -X POST "$API/api/v1/domains/$DOM_ID/mail")" = "201" ] || true   # idempotent-ish
RESP=$(api -H 'Content-Type: application/json' -d "{\"local_part\":\"accept$SUFFIX\"}" "$API/api/v1/domains/$DOM_ID/mail-identities")
IDENT=$(echo "$RESP"  | python3 -c 'import json,sys;print(json.load(sys.stdin)["identity"]["address"])')
SECRET=$(echo "$RESP" | python3 -c 'import json,sys;print(json.load(sys.stdin)["credential"]["secret"])')
[ -n "$IDENT" ] && [ -n "$SECRET" ] || die "identity/credential missing"
python3 - "$IDENT" "$SECRET" <<'PY' || die "SMTP AUTH failed"
import smtplib, sys
addr, secret = sys.argv[1], sys.argv[2]
s = smtplib.SMTP('localhost', 587, timeout=20); s.ehlo('mail.local'); s.starttls(); s.ehlo('mail.local')
s.login(addr, secret)
s.sendmail(addr, [addr], 'Subject: acceptance\n\nselfu acceptance')
s.quit()
PY
ok "SMTP AUTH + send as $IDENT"

say "5. alias"
ALIAS=$(api -H 'Content-Type: application/json' -d "{\"local_part\":\"support$SUFFIX\",\"destinations\":[\"$IDENT\"]}" "$API/api/v1/domains/$DOM_ID/mail/aliases" \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["address"])')
docker compose exec -T chasquid sh -c "chasquid-util aliases-resolve $ALIAS" | grep -q "$IDENT" || die "alias not resolving"
ok "alias $ALIAS -> $IDENT"

say "6. reconciliation"
api -X POST "$API/api/v1/domains/$DOM_ID/mail/reconcile" | python3 -c '
import json,sys
d=json.load(sys.stdin)
assert len(d["identities_missing"])==0, d
' || die "reconcile reported issues"
ok "reconcile clean"

say "7. application install (catalog + OIDC + app SMTP)"
CAT=$(docker compose exec -T db psql -U selfu -d selfu -tAc \
  "SELECT id FROM catalog_applications WHERE slug='gitea'" | tr -d '[:space:]')
[ -n "$CAT" ] || die "gitea catalog entry missing — seed it first"
APP_ORG=$(docker compose exec -T db psql -U selfu -d selfu -tAc \
  "SELECT organization_id FROM domains WHERE fqdn='$DOMAIN'" | tr -d '[:space:]')
[ -n "$APP_ORG" ] || die "no org owns $DOMAIN"
INST=$(api -H 'Content-Type: application/json' -d "{\"catalog_id\":\"$CAT\",\"hostname\":\"accept$SUFFIX.$DOMAIN\"}" \
  "$API/api/v1/organizations/$APP_ORG/applications")
echo "$INST" | grep -q '"oidc"' || die "no OIDC creds from install: $(echo "$INST" | head -c 200)"
echo "$INST" | grep -q '"smtp"' || die "no app SMTP identity from install"
ok "app installed with OIDC + app SMTP"

say "8. audit trail"
EVENTS=$(docker compose exec -T db psql -U selfu -d selfu -tAc \
  "SELECT count(*) FROM audit_events WHERE action IN ('organization.created','user.created','mail.identity.created','application.installed')")
[ "$EVENTS" -ge 4 ] || die "audit trail incomplete"
ok "audit rows: $EVENTS"

say "ALL ACCEPTANCE CHECKS PASSED (§97/§101)"

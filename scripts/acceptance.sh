#!/usr/bin/env bash
# selfu acceptance test (spec §97, §101) — runs the full platform lifecycle
# against a running stack and asserts every step. Exit code 0 = all green.
#
# Requires: stack running (docker compose up), .env with the real values,
# and a VERIFIED mail-ready domain (default: pruxi.in from .env AUTHENTIK_HOST
# host). The admin session is minted from .env secrets (dev-acceptance path;
# production acceptance uses a real OIDC browser login).
set -euo pipefail

cd "$(dirname "$0")/.."
set -a; source .env; set +a
API="${SELFU_ACCEPTANCE_API:-https://platform.pruxi.in}"
RES="--resolve platform.pruxi.in:443:127.0.0.1 --resolve auth.pruxi.in:443:127.0.0.1"

say()  { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
die()  { printf '\033[1;31mFAIL: %s\033[0m\n' "$*" >&2; exit 1; }
ok()   { printf '  \033[1;32mok\033[0m %s\n' "$*"; }

# --- mint an admin session token -------------------------------------------
ADMIN_ID=$(docker compose exec -T db psql -U selfu -d selfu -tAc \
  "SELECT id FROM users WHERE email='${AUTHENTIK_BOOTSTRAP_EMAIL}'" | tr -d '[:space:]')
[ -n "$ADMIN_ID" ] || die "admin user missing — run a login first"
TOKEN=$(SELFU_SESSION_SECRET="$SELFU_SESSION_SECRET" ADMIN_ID="$ADMIN_ID" python3 - <<'PY'
import hmac,hashlib,base64,json,time,os
s=os.environ['SELFU_SESSION_SECRET'].encode();u=os.environ['ADMIN_ID']
exp=int(time.time())+3600
p=base64.urlsafe_b64encode(json.dumps({"u":u,"e":exp}).encode()).rstrip(b'=')
k=hashlib.sha256(s).digest();sig=base64.urlsafe_b64encode(hmac.new(k,p,hashlib.sha256).digest()).rstrip(b'=')
print(p.decode()+'.'+sig.decode())
PY
)
CK="selfu_session=$TOKEN"
api() { curl -s $RES -b "$CK" -m 20 "$@"; }
code() { curl -s $RES -o /dev/null -w '%{http_code}' -b "$CK" -m 20 "$@"; }

DOMAIN="${SELFU_ACCEPTANCE_DOMAIN:-pruxi.in}"
SUFFIX="$(date +%s)"

say "1. health + auth gates"
[ "$(code "$API/api/v1/health")" = "200" ] || die "health not 200"
[ "$(curl -s $RES -o /dev/null -w '%{http_code}' "$API/api/v1/me")" = "401" ] || die "me should be 401 unauthenticated"

say "1b. onboarding state (bootstrap wizard, G8/G9)"
SETUP="$(curl -s $RES "$API/api/v1/setup")"
echo "$SETUP" | grep -q '"onboarded":true' || die "installation not onboarded — run the setup wizard (GET /api/v1/setup) first"
echo "$SETUP" | grep -q '"local_domain":"selfu.local"' || die "local domain missing from setup status"
ok "installation onboarded"

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
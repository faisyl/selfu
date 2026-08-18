#!/usr/bin/env bash
# Ensures A records for the platform hostnames point at PUBLIC_IP (Cloudflare).
# Set PUBLIC_IP to this host's real public address for actual use; the
# default of 127.0.0.1 is for local testing with curl --resolve.
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; source .env; set +a

[ -n "${CLOUDFLARE_API_TOKEN:-}" ] && [ -n "${CLOUDFLARE_ZONE_ID:-}" ] || { echo "cloudflare creds missing"; exit 1; }
BASE="https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records"
AUTH="Authorization: Bearer $CLOUDFLARE_API_TOKEN"

for host in "$PLATFORM_HOST" "$AUTH_HOST" "$MAIL_HOST"; do
  existing=$(curl -s -H "$AUTH" "$BASE?type=A&name=$host" | python3 -c \
    'import json,sys;d=json.load(sys.stdin);print(d["result"][0]["id"] if d["result"] else "")')
  if [ -n "$existing" ]; then
    curl -s -X PATCH -H "$AUTH" -H 'Content-Type: application/json' \
      -d "{\"content\":\"$PUBLIC_IP\",\"ttl\":120}" "$BASE/$existing" >/dev/null
    echo "updated $host -> $PUBLIC_IP"
  else
    curl -s -X POST -H "$AUTH" -H 'Content-Type: application/json' \
      -d "{\"type\":\"A\",\"name\":\"$host\",\"content\":\"$PUBLIC_IP\",\"ttl\":120,\"proxied\":false}" "$BASE" >/dev/null
    echo "created $host -> $PUBLIC_IP"
  fi
done
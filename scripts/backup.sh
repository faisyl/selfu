#!/usr/bin/env bash
# selfu backup (spec §93): PostgreSQL (platform + authentik) dumps plus the
# chasquid configuration/data volumes. Restore = restore the dumps and the
# volume tarballs on a fresh host before `docker compose up` (§94).
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; source .env; set +a

STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="backups/$STAMP"
mkdir -p "$OUT"

echo "== backing up PostgreSQL =="
docker compose exec -T db pg_dump -U selfu -d selfu -Fc > "$OUT/selfu.dump"
docker compose exec -T db pg_dump -U selfu -d authentik -Fc > "$OUT/authentik.dump"

echo "== backing up chasquid volumes (config + data = queue, userdb, DKIM keys) =="
for v in chasquid-etc chasquid-data; do
  docker run --rm \
    -v "selfu_$v:/vol:ro" \
    -v "$PWD/$OUT:/backup" \
    alpine:3.21 tar czf "/backup/$v.tar.gz" -C /vol . 
done

echo "== done =="
ls -la "$OUT"
#!/bin/sh
# Minimal mail spool MDA for the selfu platform (G4a). Real message storage
# is decided later; this keeps raw messages for debugging and future
# migration. Invoked by chasquid with: -f %from% -d %to_user%.
set -e
from=""
to=""
while [ $# -gt 1 ]; do
  case "$1" in
    -f) from="$2"; shift 2 ;;
    -d) to="$2"; shift 2 ;;
    *) shift ;;
  esac
done
[ -n "$to" ] || to="unknown"
dir="/data/spool/$to"
mkdir -p "$dir"
stamp=$(date +%s%N)
{
  echo "From: $from"
  echo "Delivered-To: $to"
  echo
  cat
} > "$dir/message-$stamp.eml"
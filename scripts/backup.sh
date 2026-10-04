#!/usr/bin/env bash
# Copy the database, snapshots, and logs. The archive includes .env when present.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${1:-port-warden-backup-$STAMP.tgz}"

tar -czf "$OUT" data .env 2>/dev/null || tar -czf "$OUT" data
echo "Wrote $OUT"
echo "This archive may contain the admin password hash, session material, and .env secrets."
echo "Restore does not change nftables. Apply a snapshot only with scripts/rollback-firewall.sh."

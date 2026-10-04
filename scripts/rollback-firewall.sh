#!/usr/bin/env bash
# Re-apply a previously saved nftables snapshot. Refuses to run without --yes.
set -euo pipefail

YES=0
FILE=""
for arg in "$@"; do
  case "$arg" in
    --yes) YES=1 ;;
    *) FILE="$arg" ;;
  esac
done

if [[ "$YES" -ne 1 || -z "$FILE" ]]; then
  echo "Usage: scripts/rollback-firewall.sh --yes path/to/snapshot.nft" >&2
  exit 2
fi

if [[ ! -f "$FILE" ]]; then
  echo "Snapshot not found: $FILE" >&2
  exit 1
fi

if grep -E '^[[:space:]]*(delete|flush)[[:space:]]+ruleset' "$FILE" >/dev/null; then
  echo "Refusing snapshot that flushes or deletes the whole ruleset." >&2
  exit 1
fi

if ! grep -q 'table inet port_warden' "$FILE"; then
  echo "Refusing snapshot that does not target inet port_warden." >&2
  exit 1
fi

nft -c -f "$FILE"
nft -f "$FILE"
echo "Applied $FILE"

#!/usr/bin/env bash
# Stop Port Warden. Does not delete data or nftables unless you pass the matching flags.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PURGE_DATA=0
REMOVE_FIREWALL=0
for arg in "$@"; do
  case "$arg" in
    --purge-data) PURGE_DATA=1 ;;
    --remove-firewall) REMOVE_FIREWALL=1 ;;
    *) echo "Unknown argument: $arg" >&2; exit 2 ;;
  esac
done

if command -v docker >/dev/null 2>&1 && [[ -f docker-compose.yml ]]; then
  docker compose --profile honeypots down || true
fi

if [[ "$REMOVE_FIREWALL" -eq 1 ]]; then
  echo "This deletes only table inet port_warden. Other firewall tables stay."
  echo "Type DELETE PORT WARDEN TABLE to continue."
  read -r answer
  if [[ "$answer" != "DELETE PORT WARDEN TABLE" ]]; then
    echo "Firewall table left in place."
  elif command -v nft >/dev/null 2>&1; then
    nft delete table inet port_warden
    echo "Deleted table inet port_warden."
  else
    echo "nft is not installed; table not deleted." >&2
    exit 1
  fi
else
  echo "Host nftables table was left unchanged."
fi

if [[ "$PURGE_DATA" -eq 1 ]]; then
  rm -rf data
  echo "Removed the local data directory."
else
  echo "Data directory kept. Remove it yourself after you have a backup."
fi

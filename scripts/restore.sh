#!/usr/bin/env bash
# Extract a backup. Does not start the service and does not call nft.
set -euo pipefail

if [[ "${1:-}" != "--yes" || -z "${2:-}" ]]; then
  echo "Usage: scripts/restore.sh --yes backup.tgz" >&2
  echo "Stop Port Warden first. This overwrites ./data and, if present in the archive, .env." >&2
  exit 2
fi

tar -tzf "$2" >/dev/null
tar -xzf "$2"
echo "Restored $2"
echo "The host firewall was not modified."

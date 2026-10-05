#!/usr/bin/env bash
# Reinstall the last confirmed Port Warden table after boot.
# Does nothing if no last-good file exists. Does not flush other tables.
# Skips "flush table" when the table is not loaded yet (fresh boot).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FILE="${1:-$ROOT/data/last-good.nft}"

if [[ ! -f "$FILE" ]]; then
  echo "No last-good ruleset at $FILE; host firewall unchanged."
  exit 0
fi

if grep -E '^[[:space:]]*(delete|flush)[[:space:]]+ruleset' "$FILE" >/dev/null; then
  echo "Refusing last-good file that flushes the whole ruleset." >&2
  exit 1
fi

if ! grep -q 'table inet port_warden' "$FILE"; then
  echo "Refusing last-good file that does not target inet port_warden." >&2
  exit 1
fi

if ! command -v nft >/dev/null 2>&1; then
  echo "nft is not installed." >&2
  exit 1
fi

prepared="$(mktemp)"
trap 'rm -f "$prepared"' EXIT
if nft list table inet port_warden >/dev/null 2>&1; then
  cp "$FILE" "$prepared"
else
  grep -v -E '^[[:space:]]*(table inet port_warden|flush table inet port_warden)$' "$FILE" >"$prepared"
fi

nft -c -f "$prepared"
nft -f "$prepared"
echo "Restored $FILE"

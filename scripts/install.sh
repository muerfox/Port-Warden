#!/usr/bin/env bash
# Prepare Port Warden directories. This does not change nftables.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

mkdir -p data/logs data/snapshots data/honeypot
chmod 700 data data/logs data/snapshots || true
chmod 1777 data/honeypot || true

if [[ ! -f .env ]]; then
  cp .env.example .env
  echo "Created .env from .env.example."
  echo "Edit PORT_WARDEN_SECRET_KEY and PORT_WARDEN_ADMIN_PASSWORD before starting."
fi

if command -v python3 >/dev/null 2>&1; then
  python3 -m venv .venv
  .venv/bin/pip install --upgrade pip
  .venv/bin/pip install -r requirements.txt
fi

echo
echo "No firewall changes were made."
echo "Host UI: .venv/bin/python -m app"
echo "Containers: docker compose up -d --build"
echo "Apply nftables only from the dashboard preview, or install host-agent/port-warden-agent.service."
echo "If you use Docker, chown the data directory to uid 10001 so the container can write its database."

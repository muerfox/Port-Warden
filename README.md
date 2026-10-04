# Port Warden

Port Warden is a defensive host firewall desk for a Linux server you administer. It keeps desired nftables policy in SQLite, shows listening ports, records JSON events, and can temporarily ban SSH password-guessing. Honeypots are opt-in and do not run commands.

The default nft backend is **disabled**. Preview and apply stage a ruleset. They do not change the host until you point the service at the host agent or run the optional host-network compose file.

## Defaults

| Choice | Value |
| --- | --- |
| OS / firewall | Generic Linux, nftables table `inet port_warden` |
| App | Python 3.12, FastAPI, SQLite, server-rendered UI |
| Management bind | `127.0.0.1:8443` |
| Enforcement | Off until you select the agent or local backend |
| Brute force | 5 failures in 10 minutes, 1 hour ban, no automatic permanent bans, no automatic nft update |
| Honeypots | Off |

firewalld and iptables are not implemented. Docker does not secure the host by itself: a bridge container does not own the host firewall, and routers, NAT, and cloud security groups still decide what the internet can reach.

## Layout

```text
app/                 API, UI, firewall, bans, inventory
honeypots/decoy.py   low-interaction SSH and HTTP decoys
host-agent/          root helper that applies only this table
docs/                architecture, threat model, API, deployment, checklist
docker-compose.yml   dashboard only, loopback publish, no NET_ADMIN
scripts/             install, uninstall, rollback, backup, restore
tests/
```

## Setup from scratch (Docker)

Use this path on a clean machine. It builds the image and serves the UI on port **9090** on all interfaces (`0.0.0.0`). The default nft backend stays disabled, so this does not change the host firewall. Inbound TCP 80, 443, and 8080 are excluded from the drop policy when a ruleset is later applied.

1. Install Docker Engine and the Compose plugin, then start the daemon.

   ```bash
   # Fedora / RHEL-like
   sudo dnf install -y docker docker-compose-plugin
   sudo systemctl enable --now docker
   sudo usermod -aG docker "$USER"
   # log out and back in (or: newgrp docker)
   ```

   ```bash
   # Debian / Ubuntu
   sudo apt update
   sudo apt install -y docker.io docker-compose-v2
   sudo systemctl enable --now docker
   sudo usermod -aG docker "$USER"
   # log out and back in (or: newgrp docker)
   ```

2. Get the source.

   ```bash
   git clone https://github.com/muerfox/Port-Warden.git
   cd Port-Warden
   ```

3. Create `.env` (required — older Compose only accepts a string `env_file` path, so the file must exist).

   ```bash
   cp .env.example .env
   # set at least:
   #   PORT_WARDEN_SECRET_KEY=<long random string>
   #   PORT_WARDEN_ADMIN_USERNAME=admin
   #   PORT_WARDEN_ADMIN_PASSWORD=<12+ characters>
   #
   # Local trial example:
   #   PORT_WARDEN_SECRET_KEY=compose-dev-secret-change-me-please
   #   PORT_WARDEN_ADMIN_PASSWORD=portwarden-change-me
   ```

4. Build and start.

   ```bash
   mkdir -p data
   docker compose up --build
   # detached:
   # docker compose up -d --build
   ```

5. Open the UI and sign in.

   - URL: `http://<host>:9090/` (bound on all interfaces)
   - Health: `curl -s http://127.0.0.1:9090/health`
   - Login: username/password from `.env`

6. Stop.

   ```bash
   docker compose down
   ```

Host nftables apply, the root agent, rollback, backup, and honeypots are in [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md). Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before enforce mode.

## Setup from scratch (Python, no Docker)

Needs Python 3.12+.

```bash
git clone https://github.com/muerfox/Port-Warden.git
cd Port-Warden
./scripts/install.sh
cp .env.example .env
# edit PORT_WARDEN_SECRET_KEY and PORT_WARDEN_ADMIN_PASSWORD (12+)
# keep PORT_WARDEN_BIND_HOST=127.0.0.1 and PORT_WARDEN_EXPOSE_PUBLIC=0
.venv/bin/python -m app
```

UI: `http://127.0.0.1:8443/`. Tests: `.venv/bin/pytest`.

## Firewall behavior that matters

- Named rules support address, protocol, ports, direction, comment, expiry, and priority.
- Presets fill a form. They do not open ports.
- Inbound TCP 80, 443, and 8080 are excluded from the drop: they are accepted before denylist, bans, and enforce mode. Change them with `PORT_WARDEN_EXCLUDED_PORTS`.
- Allowlist and management addresses cannot be banned.
- Apply from an SSH client that the new policy would drop requires the confirmation phrase.
- If `nft` fails after a previous good apply, the last good script is installed again.
- If this process stops, the kernel keeps the last successful table. Startup does not flush it.

## Logs

Events are JSON lines in `data/logs/port-warden.jsonl` with timestamp, event type, source IP, destination port, action, and rule id when there is one. Passwords and tokens are removed. Retention defaults to 30 days. Details are in [docs/DATA_MODEL.md](docs/DATA_MODEL.md). The HTTP API is [docs/API.md](docs/API.md).

## Honeypots

`docker compose --profile honeypots up -d` after you mark a decoy on in the UI. They are isolated, low-interaction, and documented in [docs/HONEYPOTS.md](docs/HONEYPOTS.md). The UI vendored copy of htmx 2.0.4 is under the Zero-Clause BSD license in `app/web/static/htmx.LICENSE.txt`.

## Later, not in this version

firewalld/ufw adapters, more than one node, a packet-inspecting WAF, community blocklist sync, eBPF, and a Kubernetes operator.

Review [docs/SECURITY_CHECKLIST.md](docs/SECURITY_CHECKLIST.md) before you rely on it.

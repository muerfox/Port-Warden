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

## Run

```bash
./scripts/install.sh
# edit .env: SECRET_KEY and ADMIN_PASSWORD (12+ characters)
.venv/bin/python -m app
```

Open `http://127.0.0.1:8443/`. Health check: `GET /health`.

Docker:

```bash
docker compose up --build
```

UI at `http://127.0.0.1:9000/` (default login `admin` / `portwarden-change-me`). Put real secrets in `.env`. Host agent, rollback, and backup are in [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md). Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before applying enforce mode.

```bash
.venv/bin/pytest
```

## Firewall behavior that matters

- Named rules support address, protocol, ports, direction, comment, expiry, and priority.
- Presets fill a form. They do not open ports.
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

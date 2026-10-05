# Port Warden

Port Warden is a defensive host firewall desk for a Linux server you administer. It keeps desired nftables policy in SQLite, shows host listening ports, records JSON events, and can temporarily ban SSH password-guessing. Honeypots are opt-in and do not run commands.

Default Docker Compose uses the **host network** and the **local** nft backend so inventory sees host listeners (including SSH on 2222) and Apply installs `table inet port_warden` in front of inbound host traffic. Preview and confirm are still required before Apply. It is not `--privileged`.

## Defaults

| Choice | Value |
| --- | --- |
| OS / firewall | Generic Linux, nftables table `inet port_warden` |
| App | Python 3.12, FastAPI, SQLite, server-rendered UI |
| Docker UI | `https://0.0.0.0:9090/` (self-signed, 10-year cert from image build) |
| Enforcement | Local nft on host network after Preview/Apply |
| Open ports | Discovered on the Ports panel; keep open / set SSH there (UI bind stays open) |
| Brute force | 5 failures in 10 minutes, 1 hour ban, no automatic permanent bans, no automatic nft update |
| Honeypots | Off |

firewalld and iptables are not adapters in this version. Cloud security groups and upstream routers still apply. A bridge-only dashboard mode remains in `docker-compose.dashboard.yml` if you do not want host firewall control.

## Layout

```text
app/                 API, UI, firewall, bans, inventory, traffic graphs
honeypots/decoy.py   low-interaction SSH and HTTP decoys
host-agent/          optional root helper that applies only this table
docs/                architecture, threat model, API, deployment, checklist
docker-compose.yml   host network + NET_ADMIN + local nft
scripts/             install, uninstall, rollback, backup, restore
tests/
```

## Setup from scratch (Docker)

Use this path on a clean machine. The image build creates a self-signed certificate valid for 10 years and serves HTTPS on port **9090**. Compose shares the host network namespace so the Ports page lists host listeners and Apply can install the host firewall table.

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

3. Create `.env` (secrets and your admin CIDR). You do **not** list service ports here.

   ```bash
   cp .env.example .env
   # required secrets:
   #   PORT_WARDEN_SECRET_KEY=<long random string>
   #   PORT_WARDEN_ADMIN_USERNAME=admin
   #   PORT_WARDEN_ADMIN_PASSWORD=<12+ characters>
   # put your admin source so management SSH stays reachable after Apply:
   #   PORT_WARDEN_MANAGEMENT_CIDRS=203.0.113.10/32,127.0.0.1/32,::1/128
   ```

4. Build and start.

   ```bash
   mkdir -p data
   docker compose up --build
   # detached:
   # docker compose up -d --build
   ```

5. Open the UI and sign in.

   - URL: `https://<host>:9090/` (self-signed)
   - Health: `curl -sk https://127.0.0.1:9090/health`
   - Login: username/password from `.env`
   - Ports page lists host listeners automatically (for example SSH on 2222)

6. Put the firewall in front of the host.

   1. Open **Ports**. Confirm it shows host listeners.
   2. For each service that should stay reachable, click **Keep open**. SSH is auto-detected from the `sshd` process.
   3. Firewall → Preview → read the lockout warning → Apply.
   4. Enforce mode drops inbound traffic that is not established, loopback, management SSH, allowlisted, kept open, or matched by an allow rule.

7. Stop.

   ```bash
   docker compose down
   ```

Stopping the container does **not** remove an already applied `inet port_warden` table. Rollback, backup, and honeypots are in [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md). Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before enforce mode.

## Setup from scratch (Python, no Docker)

Needs Python 3.12+.

```bash
git clone https://github.com/muerfox/Port-Warden.git
cd Port-Warden
./scripts/install.sh
cp .env.example .env
# edit .env: secret, admin password, bind 127.0.0.1, expose_public 0
# for host enforcement use the host-agent or CAP_NET_ADMIN with nft_backend=local
.venv/bin/python -m app
```

UI: `http://127.0.0.1:8443/`. Tests: `.venv/bin/pytest`.

## Firewall behavior that matters

- Named rules support address, protocol, ports, direction, comment, expiry, and priority.
- Presets fill a form. They do not open ports.
- The Ports panel shows process and service for each listener. Keep open what should stay reachable. SSH is auto-detected from `sshd`. The UI bind port stays open automatically.
- Allowlist and management addresses cannot be banned.
- Apply from an SSH client that the new policy would drop requires the confirmation phrase.
- If `nft` fails after a previous good apply, the last good script is installed again.
- If this process stops, the kernel keeps the last successful table. Startup does not flush it.

## Logs

Events are JSON lines in `data/logs/port-warden.jsonl` with timestamp, event type, source IP, destination port, action, and rule id when there is one. Passwords and tokens are removed. Retention defaults to 30 days. Details are in [docs/DATA_MODEL.md](docs/DATA_MODEL.md). The HTTP API is [docs/API.md](docs/API.md).

## Honeypots

Opt-in with Compose profile `honeypots`. Do not enable the SSH decoy on port 2222 if the host already uses 2222 for real SSH. See [docs/HONEYPOTS.md](docs/HONEYPOTS.md).

## Security checklist

Use [docs/SECURITY_CHECKLIST.md](docs/SECURITY_CHECKLIST.md) before exposing the dashboard or applying enforce mode.

# Deployment

## Requirements

- Linux with nftables if you want enforcement. The dashboard itself runs without `nft`.
- Python 3.12 for a host install, or Docker.
- To apply rules: root, or `CAP_NET_ADMIN` in the host network namespace. Reading auth logs may also require membership in `adm` or access to the journal.
- This program does not disable firewalld, ufw, or cloud security groups. If another input filter is active, read the priority note below before applying.

## Install

```bash
./scripts/install.sh
```

Edit `.env`. Set a long `PORT_WARDEN_SECRET_KEY` and an admin password of at least 12 characters. Leave `PORT_WARDEN_EXPOSE_PUBLIC=0` and `PORT_WARDEN_BIND_HOST=127.0.0.1` on a host install.

```bash
.venv/bin/python -m app
```

The UI is at `http://127.0.0.1:8443/`. Startup does not change nftables.

For enforcement, run `host-agent/port-warden-agent.service` as root, put a mode-0600 token in `/etc/port-warden/agent.token`, and set:

```bash
PORT_WARDEN_NFT_BACKEND=agent
```

`deploy/port-warden.service` runs the dashboard without `CAP_NET_ADMIN`.

## Docker (host firewall)

```bash
# Required: Compose env_file is a path string (compatible with older docker compose).
cp .env.example .env
# If sshd listens on 2222:
#   PORT_WARDEN_SSH_PORT=2222
# Before the first enforce Apply, add your admin CIDR:
#   PORT_WARDEN_MANAGEMENT_CIDRS=<your-ip>/32,127.0.0.1/32,::1/128
docker compose up --build
# or detached:
docker compose up -d --build
```

UI: `https://<host>:9090/` (all interfaces). The image build writes a self-signed certificate at `/etc/port-warden/tls/` valid for 3650 days (10 years). Browsers show a warning. Login uses `PORT_WARDEN_ADMIN_*` from `.env`.

Default Compose:

- Uses **host network** so Ports shows host listeners (including SSH on 2222) and nftables changes the host
- Adds `CAP_NET_ADMIN` (not `--privileged`) and keeps it across the uid drop via `setpriv`
- Sets `PORT_WARDEN_NFT_BACKEND=local` and `PORT_WARDEN_HOST_NETWORK=1`
- Listens on HTTPS **9090** on `0.0.0.0`
- Accepts inbound TCP **80, 443, 8080, 9090** before denylist, bans, and the enforce drop (`PORT_WARDEN_EXCLUDED_PORTS`)
- Drops other capabilities, `no-new-privileges`, read-only root filesystem, memory and pid limits

After Preview/Apply in enforce mode, `table inet port_warden` runs at input priority `-10` and sits in front of later filters for unmatched traffic. Management SSH stays open only for `PORT_WARDEN_MANAGEMENT_CIDRS` on `PORT_WARDEN_SSH_PORT`.

Dashboard-only (no host firewall): `docker compose -f docker-compose.dashboard.yml up --build`.

`--privileged` is not required. Do not use it.

Stopping the container leaves any previously applied `inet port_warden` table in the kernel.

## Apply and roll back

1. Edit rules in the UI. Nothing is installed yet.
2. Open Firewall and preview. Read the diff and the lockout warning.
3. Apply. Disabled backend: a file is written to `data/staged.nft` and the host is unchanged. Agent or local backend: `nft` installs the table.
4. Roll back from the UI, or run `scripts/rollback-firewall.sh --yes data/snapshots/<file>.nft` after reading the file.

`scripts/uninstall.sh` stops Compose and leaves the table. It deletes the table only with `--remove-firewall` and the confirmation phrase. `--purge-data` removes `./data`.

## Backup

`scripts/backup.sh` archives `data/` and `.env`. The archive contains secrets. `scripts/restore.sh --yes backup.tgz` extracts it and does not call `nft`. Stop the service before restoring the database.

Logs: the process rotates `data/logs/port-warden.jsonl` by size and deletes rotated files past `log_retention_days`. `deploy/logrotate/port-warden` is an additional host logrotate snippet. Export events from the UI or `GET /api/v1/events/export`.

## Honeypots

See `docs/HONEYPOTS.md`. They stay off until you opt in.

## nftables priority

The input chain uses priority -10, which is earlier than the usual filter priority 0. In enforce mode the chain policy is drop, so this table becomes the inbound policy for packets it sees. Disable or account for ufw/firewalld before relying on it. Established SSH sessions are accepted, and management CIDRs keep an SSH allow. That does not help if you apply from an address that is not covered, which is why the lockout check exists.

## Update

Pull the tree, rebuild the venv or image, restart the service. Do not flush nftables as part of the update. The previous table remains until you preview and apply a new one.

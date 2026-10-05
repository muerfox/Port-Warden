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
# Before the first enforce Apply, add your admin CIDR:
#   PORT_WARDEN_MANAGEMENT_CIDRS=<your-ip>/32,127.0.0.1/32,::1/128
# Service ports are chosen in the Ports panel after discovery (Keep open). SSH is auto-detected.
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
- Discovers host listeners on the Ports panel; open ports and management SSH are chosen there
- Drops other capabilities, read-only root filesystem, memory and pid limits

After Preview/Apply in enforce mode, `table inet port_warden` runs at input priority `-10` and sits in front of later filters for unmatched traffic. Management SSH stays open only for `PORT_WARDEN_MANAGEMENT_CIDRS` on the SSH port you marked in the panel.

Dashboard-only (no host firewall): `docker compose -f docker-compose.dashboard.yml up --build`.

`--privileged` is not required. Do not use it.

Stopping the container leaves any previously applied `inet port_warden` table in the kernel. A reboot clears kernel tables. With `PORT_WARDEN_RESTORE_ON_START=1` (the Compose default), the next start reinstalls `data/last-good.nft` only after an administrator has applied once. Host installs can also enable `deploy/port-warden-firewall.service`, which runs `scripts/restore-last-good.sh` before the network is fully online.

## Production baseline

Enforce mode is a host input filter at nftables priority `-10`. It is meant for a generic Linux server, not a single distribution:

- Invalid state is dropped. Established and related traffic is accepted. Loopback is accepted.
- ICMP errors, IPv6 neighbor discovery, rate-limited ping, and DHCP client replies stay open so address configuration and path MTU keep working.
- Management SSH is limited to `PORT_WARDEN_MANAGEMENT_CIDRS` on the auto-detected sshd port.
- Ports you keep open, protection packs, allow/deny lists, and named rules follow.
- Everything else is logged (rate-limited) and dropped.
- Only table `inet port_warden` is replaced. firewalld, ufw, and cloud security groups are not removed.
- The first Apply is still an explicit preview. Startup never invents a new policy.

Install nftables (`nft`) on the host. If firewalld is active, this table still runs earlier at priority `-10`. Read both before the first enforce Apply.

```bash
sudo install -d -m 700 /var/lib/port-warden
sudo cp deploy/port-warden-firewall.service /etc/systemd/system/
sudo systemctl enable --now port-warden-firewall.service
```

Point that unit at the same `last-good.nft` the app writes (`PORT_WARDEN_DATA_DIR`, default `./data` or `/var/lib/port-warden` in Compose).

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

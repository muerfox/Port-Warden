# Architecture

Port Warden is a single-host firewall desk. Desired state is stored in SQLite. nftables enforces it only after an administrator previews a diff and confirms apply.

## Decisions

- Target is generic Linux with nftables. firewalld and iptables are not adapters in this version.
- The service is Python 3.12, FastAPI, SQLite, and server-rendered pages.
- Default Docker Compose uses host network, host PID (`pid: host`), `nft_backend: local`, and `CAP_NET_ADMIN` so inventory (including process labels) and Apply operate on the host. A bridge-only dashboard file remains for non-enforcing installs. The host-agent Unix helper is still available when you prefer not to give the API `NET_ADMIN`.
- The management UI binds to loopback unless `expose_public` is set. Docker Compose listens on `0.0.0.0:9090` as HTTPS with a 10-year self-signed certificate from the image build.
- Listening ports are discovered from the host with process/service labels (`ss -p` and `/proc`). Operators keep ports open in the Ports panel; SSH is auto-detected from `sshd`. Choices are stored in SQLite and rendered into the nftables policy. The UI bind port is always kept open.
- Enforce mode tracks dropped TCP/UDP destination ports in dynamic nft sets (`probe_tcp` / `probe_udp`). Traffic graphs and Ports use those counters (plus auth/honeypot events) so scanned ports appear even when nothing is listening. Optional host syslog with `pw:drop` adds source IPs.
- Protection packs install early deny rules for common high-risk services (Telnet, FTP, databases, mail, RPC/NFS, Docker/K8s APIs). They update desired state only until Apply.
- Env `excluded_ports` / `ssh_port` are optional fallbacks when live detection is unavailable.

## Components

| Piece | Role |
| --- | --- |
| `app/api` | Authenticated JSON API |
| `app/web` | Status, ports, rules, lists, bans, firewall, events, honeypots, audit |
| `app/services/firewall` | Validation, nftables render, preview token, apply, rollback |
| `app/services/bruteforce` | SSH log parsing and threshold bans |
| `app/services/inventory` | Local listeners and an optional owned-address TCP check |
| `honeypots/decoy.py` | Opt-in low-interaction SSH and HTTP decoys |
| `host-agent/agent.py` | Applies only `table inet port_warden` |

## Firewall transaction

The rendered script owns `inet port_warden` and nothing else. It does not flush the host ruleset.

Input chain order:

1. Drop invalid connection tracking state.
2. Accept established and related traffic.
3. Accept loopback.
4. Accept IPv4/IPv6 ICMP needed for errors and path MTU, rate-limited echo requests, and IPv6 neighbor discovery.
5. Accept DHCP client replies (DHCPv4 and DHCPv6).
6. Accept management CIDRs to the configured SSH port.
7. Accept excluded inbound TCP ports.
8. Accept allowlist entries.
9. Drop denylist entries that do not contain a protected range.
10. Drop bans that do not contain a protected or allowlisted range.
11. Named rules, lowest priority number first.
12. Enforce mode logs and drops what remains. Monitor mode policy is accept.

Gateway mode (off by default) adds a forward chain and an optional postrouting masquerade in the same table. LAN and `wg0` may leave via the active WAN. New WAN-originated flows are dropped, or queued to Suricata when IPS is enabled. `ip_forward` is turned on only after a successful Apply and restored on rollback to a non-gateway ruleset. Dual-WAN failover health-checks the primary gateway address and moves masquerade plus fwmark `0x7077` to the backup.

Stopping the API does not remove the table. Startup does not install or flush rules. A failed apply reinstalls the last good script when one exists.

Monitor mode runs at priority -10. An accept verdict there can stop a later firewall from seeing the packet. The UI makes that explicit before the mode is stored.

## What Docker still does not do

The default Compose file uses the host network so nftables and inventory target the host. A bridge-only container (`docker-compose.dashboard.yml`) cannot protect the host. Cloud security groups, upstream routers, and other host firewalls still apply. See `docs/DEPLOYMENT.md` and `docs/THREAT_MODEL.md`.

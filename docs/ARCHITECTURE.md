# Architecture

Port Warden is a single-host firewall desk. Desired state is stored in SQLite. nftables enforces it only after an administrator previews a diff and confirms apply.

## Decisions

- Target is generic Linux with nftables. firewalld and iptables are not adapters in this version.
- The service is Python 3.12, FastAPI, SQLite, and server-rendered pages.
- Default nft backend is `disabled`. Apply writes a snapshot and does not call `nft`.
- The preferred way to change the host is `host-agent/agent.py`, a root helper on a Unix socket. The alternative is `nft_backend: local` in the host network namespace with `CAP_NET_ADMIN`.
- The management UI binds to loopback unless `expose_public` is set. Docker Compose publishes `127.0.0.1:8443` and sets that flag only inside the container network namespace.

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
4. Accept management CIDRs to the configured SSH port.
5. Accept allowlist entries.
6. Drop denylist entries that do not contain a protected range.
7. Drop bans that do not contain a protected or allowlisted range.
8. Named rules, lowest priority number first.
9. Enforce mode policy is drop. Monitor mode policy is accept.

Stopping the API does not remove the table. Startup does not install or flush rules. A failed apply reinstalls the last good script when one exists.

Monitor mode runs at priority -10. An accept verdict there can stop a later firewall from seeing the packet. The UI makes that explicit before the mode is stored.

## What Docker does not do

A container on a bridge network has its own network namespace. nftables commands inside it do not protect the host. Publishing a port is a Docker NAT rule, not a host policy. Cloud security groups, upstream routers, and other host firewalls still apply. See `docs/DEPLOYMENT.md` and `docs/THREAT_MODEL.md`.

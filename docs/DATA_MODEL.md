# Data model

SQLite is the desired-state store. Timestamps are UTC.

## Tables

| Table | Purpose |
| --- | --- |
| `users` | Administrator username, Argon2 password hash, optional TOTP secret |
| `sessions` | SHA-256 of the session cookie, CSRF token, expiry, client IP |
| `rules` | Named allow/deny rules: protocol, addresses, ports, direction, comment, priority, expiry |
| `ip_lists` / `ip_list_entries` | Allow and deny lists. `allowlist` and `denylist` are built in |
| `bans` | Manual and brute-force bans, permanent flag, expiry, lift time |
| `events` | Structured events: time, type, source IP, destination port, action, rule id |
| `audit_log` | Administrator actions |
| `snapshots` | Rendered nftables script, sha256, and whether it was applied |
| `honeypots` | Decoy desired state. Enabling a row does not start a container |
| `app_settings` | Firewall mode and brute-force threshold overrides |

## Rules

- `action`: `allow` or `deny`
- `direction`: `in` or `out`
- `protocol`: `tcp`, `udp`, `icmp`, or `any`
- `priority`: lower numbers are rendered first, 0 through 10000
- A rule must name an address or, for TCP/UDP, a port. A match-everything rule is rejected.
- Presets are not rows until an administrator saves them.

## Lists and bans

Allowlist entries are accepted before denylist and ban drops. A denylist or ban that contains a management CIDR or an allowlist entry is rejected. A ban must be at least a /24 (IPv4) or /64 (IPv6): larger blocks are rejected.

## Snapshots

`applied` is false when the nft backend is disabled. Those files are still written under `data/snapshots/` so you can review them. Rollback uses the previous snapshot with `applied` true, and only when a backend can call nft.

## Retention

Event and audit rows older than `log_retention_days` (default 30) are deleted on startup. Ban rows are kept so cooldown and repeat-offender counts still work. The JSON log rotates by size; only rotated files past the retention window are removed. Auth events store a source IP and a reason code, not the raw log line or username.

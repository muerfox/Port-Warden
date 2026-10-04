# HTTP API

All `/api/v1` routes except login require a session cookie. Mutating requests also require header `X-CSRF-Token` from the login or `/api/v1/auth/me` response. There is no unauthenticated admin API. `/health` is unauthenticated and returns `{"status": "ok"}`.

Interactive OpenAPI is disabled.

## Auth

| Method | Path | Body |
| --- | --- | --- |
| POST | `/api/v1/auth/login` | `username`, `password`, optional `totp` |
| POST | `/api/v1/auth/logout` | CSRF header |
| GET | `/api/v1/auth/me` | |
| POST | `/api/v1/auth/mfa/setup` | returns a TOTP secret once |
| POST | `/api/v1/auth/mfa/enable` | `code` |
| POST | `/api/v1/auth/mfa/disable` | `password`, `totp` |

If MFA is enabled and `totp` is omitted, login returns `{"mfa_required": true}` and does not set a cookie.

## Rules, lists, firewall

| Method | Path |
| --- | --- |
| GET | `/api/v1/presets` |
| GET/POST | `/api/v1/rules` |
| PATCH/DELETE | `/api/v1/rules/{id}` |
| GET/POST | `/api/v1/lists` |
| DELETE | `/api/v1/lists/{id}` |
| POST | `/api/v1/lists/{id}/entries` |
| DELETE | `/api/v1/entries/{id}` |
| GET | `/api/v1/firewall/status` |
| POST | `/api/v1/firewall/mode` |
| POST | `/api/v1/firewall/preview` |
| POST | `/api/v1/firewall/apply` |
| POST | `/api/v1/firewall/rollback` |

`POST /firewall/mode` with `mode: monitor` requires `monitor_ack: true`. Storing a mode does not install it.

Preview returns the script, a diff, warnings, `lockout_risk`, and a confirm token that expires in five minutes. Apply must send that token. If `lockout_risk` is true, also send `lockout_phrase` = `I_UNDERSTAND_LOCKOUT`.

Apply with the disabled backend returns `"applied": false`.

## Bans, inventory, logs, decoys

| Method | Path |
| --- | --- |
| GET/POST | `/api/v1/bans` |
| POST | `/api/v1/bans/{id}/unban` |
| GET/PUT | `/api/v1/bruteforce/settings` |
| POST | `/api/v1/bruteforce/ingest` |
| GET | `/api/v1/inventory/ports` |
| POST | `/api/v1/inventory/reachability` |
| GET | `/api/v1/events` |
| GET | `/api/v1/events/export` |
| GET | `/api/v1/audit` |
| GET | `/api/v1/honeypots` |
| POST | `/api/v1/honeypots/{name}/enable` |
| POST | `/api/v1/honeypots/{name}/disable` |

Reachability checks are refused unless `host:port` is listed in `PORT_WARDEN_REACHABILITY_TARGETS`. Targets must be literal IP addresses. The check is a single TCP connect, not a scan.

`ban_auto_apply` defaults off. When it is on, a new ban is pushed only if the desired ruleset already matched the last applied snapshot, so unpreviewed edits are not installed as a side effect.

Honeypot enable writes `data/honeypot/desired.json`. It does not start a container and the API does not mount the Docker socket.

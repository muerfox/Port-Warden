# Security review checklist

Use this before exposing the dashboard beyond loopback or applying enforce mode.

## Identity and session

- [ ] `PORT_WARDEN_SECRET_KEY` is a long random value and is not the sample default
- [ ] Admin password is at least 12 characters and is not stored in the repository
- [ ] `.env` and the agent token are mode 0600 and listed in `.gitignore`
- [ ] MFA is enabled for the administrator
- [ ] Cookie `Secure` is on when the UI is served over HTTPS
- [ ] Login rate limit is left at or below the default
- [ ] CSRF is required on mutating `/api/v1` routes (covered by `tests/test_access_control.py`)

## Network exposure

- [ ] Host install binds `127.0.0.1` or another private address
- [ ] `expose_public` is false on the host
- [ ] Docker publish is limited (default is host `:9000`); prefer binding `127.0.0.1:9000:8443` or put TLS in front
- [ ] The Docker socket is not mounted into the API container
- [ ] Default compose does not add `NET_ADMIN` and does not set `--privileged`

## Firewall safety

- [ ] Another host firewall (ufw, firewalld) is disabled or you accept priority -10 behavior
- [ ] Management CIDRs include the address you use for SSH
- [ ] You previewed the ruleset and read the diff
- [ ] Enforce mode was not applied with the lockout phrase unless you have a console
- [ ] A snapshot exists under `data/snapshots/` and `scripts/rollback-firewall.sh` can see `nft`
- [ ] You confirmed startup and shutdown do not flush the table
- [ ] `ban_auto_apply` stays off until you want unattended ban updates

## Logs and decoys

- [ ] Retention days match what you are willing to store
- [ ] JSON logs were checked to ensure passwords and tokens are absent
- [ ] Auth log parsing is file/journal text only; log lines are not passed to a shell
- [ ] Honeypots stay disabled until you intend to publish 2222/8088
- [ ] You have a lawful basis to record decoy source addresses
- [ ] Reachability targets, if any, are your own `ip:port` values

## Tests to re-run

```bash
.venv/bin/pytest
```

Covers rule validation, access control, brute-force thresholds, JSON logging, and failed-apply rollback.

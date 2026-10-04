# Threat model

Port Warden is for a Linux host the operator owns or is allowed to administer. It is a defensive control: inbound policy, brute-force bans, local port inventory, audit logs, and optional decoys.

## Assets

- Who can reach host services
- The nftables table `inet port_warden`
- Administrator passwords, session cookies, CSRF tokens, and the optional TOTP secret
- Ban state and the audit trail
- Decoy telemetry, which can contain source addresses and short request previews

## Adversaries

- Internet scanners and password guessers
- A process on the host that can reach the management port
- A client talking to a decoy
- A forged browser request (CSRF) while an administrator is signed in

## Assumptions

- The operator controls the host and will not point the tool at networks they do not administer.
- nftables is the enforcement point for rules this program installs. It does not replace a cloud security group, a router ACL, or another host firewall unless you choose enforce mode and accept that the early chain is authoritative.
- The host agent token and `PORT_WARDEN_SECRET_KEY` are not committed and are not world-readable.
- Decoys are used only where logging remote IP addresses is lawful for the operator.

## Out of scope

- Scanning the internet, probing scanners back, or interfering with remote systems
- A full web application firewall, eBPF packet inspection, or multi-node policy
- Proving that a listening port is reachable from the public internet
- Protecting the host if the operator grants the API container `--privileged` or an unnecessary Docker socket

## Controls

- Session cookie is HttpOnly and SameSite=Strict. Mutating API calls need a CSRF token.
- Login failures are rate limited in-process.
- Optional TOTP.
- Management bind refuses public and wildcard addresses unless `expose_public` is true.
- API documentation UI is off. `/health` returns only `{"status": "ok"}`.
- Passwords, tokens, TOTP secrets, and generated ruleset scripts are stripped from JSON logs.
- Allowlist and management ranges cannot be banned or swallowed by a denylist entry.
- Enforce apply from a client that would lose SSH requires the phrase `I_UNDERSTAND_LOCKOUT`.
- Honeypot code does not spawn a shell or open an outbound connection.

## Residual risk

`CAP_NET_ADMIN` in the host network namespace, or a root agent, can rewrite host firewall policy. A stolen admin session can stage or apply rules. Monitor mode can accept traffic before another filter runs. In-process rate limits reset when the process restarts and are not shared across workers.

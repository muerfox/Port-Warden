from __future__ import annotations

import ipaddress

from app.services.firewall.render import Policy, RuleView
from app.services.firewall.validate import contains_protected, overlaps
from app.timeutil import is_expired, utcnow


def _matches_allow(rule: RuleView, addr: ipaddress.IPv4Address | ipaddress.IPv6Address, ssh_port: int) -> bool:
    if not rule.enabled or is_expired(rule.expires_at) or rule.action != "allow" or rule.direction != "in":
        return False
    if rule.protocol not in {"tcp", "any"}:
        return False
    if rule.src_cidr:
        network = ipaddress.ip_network(rule.src_cidr, strict=False)
        if addr.version != network.version or addr not in network:
            return False
    if rule.protocol == "tcp":
        if not rule.ports:
            return True
        for part in rule.ports.split(","):
            item = part.strip()
            if "-" in item:
                start, end = (int(piece) for piece in item.split("-", 1))
                if start <= ssh_port <= end:
                    return True
            elif int(item) == ssh_port:
                return True
        return False
    return True


def _explicitly_denied(policy: Policy, addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    text = str(addr)
    if any(overlaps(text, cidr) or contains_protected(cidr, [text]) for cidr in policy.ban_cidrs):
        return True
    if any(contains_protected(cidr, [text]) or overlaps(text, cidr) for cidr in policy.deny_cidrs):
        return True
    for rule in policy.rules:
        if not rule.enabled or is_expired(rule.expires_at) or rule.action != "deny" or rule.direction != "in":
            continue
        if rule.src_cidr:
            network = ipaddress.ip_network(rule.src_cidr, strict=False)
            if addr.version != network.version or addr not in network:
                continue
        if rule.protocol in {"any", "tcp"} and (rule.protocol == "any" or not rule.ports or _port_hits(rule.ports, policy.ssh_port)):
            return True
    return False


def _port_hits(ports: str, ssh_port: int) -> bool:
    for part in ports.split(","):
        item = part.strip()
        if not item:
            continue
        if "-" in item:
            start, end = (int(piece) for piece in item.split("-", 1))
            if start <= ssh_port <= end:
                return True
        elif int(item) == ssh_port:
            return True
    return False


def evaluate_lockout(policy: Policy, admin_ip: str) -> tuple[bool, str]:
    """Return (risk, reason). Risk means this client could lose SSH."""
    if not admin_ip:
        return True, "Client IP is unknown, so lockout cannot be ruled out."
    try:
        addr = ipaddress.ip_address(admin_ip)
    except ValueError:
        return True, "Client IP is not a literal address, so lockout cannot be ruled out."

    for cidr in policy.management_cidrs:
        network = ipaddress.ip_network(cidr, strict=False)
        if addr.version == network.version and addr in network:
            return False, "Current client is inside a management CIDR that keeps SSH allowed."

    for cidr in policy.allow_cidrs:
        network = ipaddress.ip_network(cidr, strict=False)
        if addr.version == network.version and addr in network:
            if _explicitly_denied(policy, addr):
                return False, "Current client is allowlisted; allowlist entries are accepted before bans and denies."
            return False, "Current client is allowlisted."

    for rule in policy.rules:
        if _matches_allow(rule, addr, policy.ssh_port):
            return False, f"Rule {rule.name} allows SSH from the current client."

    if policy.mode == "monitor" and not _explicitly_denied(policy, addr):
        return False, "Monitor mode accepts this client because no deny or ban matches it."

    if policy.mode == "monitor":
        return True, "Monitor mode would drop SSH from the current client."
    return True, "Enforce mode would drop SSH from the current client. Add it to management CIDRs, the allowlist, or an SSH allow rule."

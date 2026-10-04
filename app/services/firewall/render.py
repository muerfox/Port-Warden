from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime

from app.services.firewall.script_guard import assert_safe_script
from app.services.firewall.validate import contains_protected, parse_ports
from app.timeutil import is_expired


@dataclass
class RuleView:
    name: str
    action: str
    direction: str
    protocol: str
    src_cidr: str | None
    dst_cidr: str | None
    ports: str | None
    comment: str
    priority: int
    enabled: bool = True
    expires_at: datetime | None = None


@dataclass
class Policy:
    mode: str
    management_cidrs: list[str]
    ssh_port: int
    allow_cidrs: list[str]
    deny_cidrs: list[str]
    ban_cidrs: list[str]
    rules: list[RuleView] = field(default_factory=list)
    excluded_ports: list[int] = field(default_factory=list)


@dataclass
class Rendered:
    script: str
    warnings: list[str]


def _active_rules(rules: list[RuleView], now: datetime) -> list[RuleView]:
    chosen = [rule for rule in rules if rule.enabled and not is_expired(rule.expires_at, now)]
    return sorted(chosen, key=lambda rule: (rule.priority, rule.name))


def _family(cidr: str) -> tuple[str, str]:
    network = ipaddress.ip_network(cidr, strict=False)
    family = "ip" if network.version == 4 else "ip6"
    shown = str(network.network_address) if network.prefixlen == network.max_prefixlen else str(network)
    return family, shown


def _split(cidrs: list[str]) -> tuple[list[str], list[str]]:
    v4: list[str] = []
    v6: list[str] = []
    for cidr in cidrs:
        network = ipaddress.ip_network(cidr, strict=False)
        bucket = v4 if network.version == 4 else v6
        bucket.append(str(network))
    return v4, v6


def _set_block(name: str, version: int, cidrs: list[str]) -> str:
    if not cidrs:
        return ""
    kind = "ipv4_addr" if version == 4 else "ipv6_addr"
    elements = ", ".join(cidrs)
    return (
        f"    set {name} {{\n"
        f"        type {kind}\n"
        f"        flags interval\n"
        f"        elements = {{ {elements} }}\n"
        f"    }}\n"
    )


def _addr(cidr: str | None, field_name: str) -> str:
    if not cidr:
        return ""
    family, shown = _family(cidr)
    return f"{family} {field_name} {shown}"


def _port_match(protocol: str, ports: list[str]) -> str:
    if len(ports) == 1 and "-" not in ports[0]:
        return f"{protocol} dport {ports[0]}"
    return f"{protocol} dport {{ {', '.join(ports)} }}"


def _comment(name: str, text: str) -> str:
    extra = f" {text}" if text else ""
    body = f"pw:{name}{extra}"[:120]
    return body.replace('"', "")


def render_named_rule(rule: RuleView) -> str:
    parts: list[str] = []
    if rule.src_cidr:
        parts.append(_addr(rule.src_cidr, "saddr"))
    if rule.dst_cidr:
        parts.append(_addr(rule.dst_cidr, "daddr"))
    if rule.protocol == "icmp":
        src_v6 = bool(rule.src_cidr and ":" in rule.src_cidr)
        parts.append("meta l4proto icmpv6" if src_v6 else "meta l4proto icmp")
    elif rule.protocol in {"tcp", "udp"}:
        ports = parse_ports(rule.ports)
        if ports:
            parts.append(_port_match(rule.protocol, ports))
        else:
            parts.append(f"meta l4proto {rule.protocol}")
    verdict = "accept" if rule.action == "allow" else "drop"
    body = " ".join(part for part in parts if part)
    comment = _comment(rule.name, rule.comment)
    if body:
        return f'        {body} {verdict} comment "{comment}"'
    return f'        {verdict} comment "{comment}"'


def render_policy(policy: Policy, now: datetime) -> Rendered:
    warnings: list[str] = []
    if policy.mode == "monitor":
        warnings.append(
            "Monitor mode uses an early accept policy. Unmatched packets are accepted here "
            "and may never reach a later host firewall. Prefer enforce mode unless this host "
            "has no other input filter."
        )
    protected = list(policy.management_cidrs)
    bans = []
    for cidr in policy.ban_cidrs:
        if contains_protected(cidr, protected) or contains_protected(cidr, policy.allow_cidrs):
            warnings.append(f"Skipped ban {cidr} because it overlaps management or the allowlist.")
            continue
        bans.append(cidr)
    denies = []
    for cidr in policy.deny_cidrs:
        if contains_protected(cidr, protected) or any(
            contains_protected(cidr, [allow]) for allow in policy.allow_cidrs
        ):
            warnings.append(f"Skipped denylist entry {cidr} because it overlaps a protected range.")
            continue
        denies.append(cidr)

    allow_v4, allow_v6 = _split(policy.allow_cidrs)
    deny_v4, deny_v6 = _split(denies)
    ban_v4, ban_v6 = _split(bans)
    inbound = [rule for rule in _active_rules(policy.rules, now) if rule.direction == "in"]
    outbound = [rule for rule in _active_rules(policy.rules, now) if rule.direction == "out"]
    if outbound:
        warnings.append(
            "Outbound rules install an output base chain at priority -10. "
            "Its accept policy can override a later outbound filter."
        )

    policy_verdict = "drop" if policy.mode == "enforce" else "accept"
    lines = [
        "# Generated by Port Warden.",
        "# Replaces only table inet port_warden. It does not flush the host ruleset.",
        "table inet port_warden",
        "flush table inet port_warden",
        "table inet port_warden {",
    ]
    lines.append(_set_block("allow_v4", 4, allow_v4))
    lines.append(_set_block("allow_v6", 6, allow_v6))
    lines.append(_set_block("deny_v4", 4, deny_v4))
    lines.append(_set_block("deny_v6", 6, deny_v6))
    lines.append(_set_block("ban_v4", 4, ban_v4))
    lines.append(_set_block("ban_v6", 6, ban_v6))
    lines.append("    chain input {")
    lines.append(f"        type filter hook input priority -10; policy {policy_verdict};")
    lines.append('        ct state invalid drop comment "pw:invalid"')
    lines.append('        ct state established,related accept comment "pw:established"')
    lines.append('        iifname "lo" accept comment "pw:loopback"')
    for cidr in policy.management_cidrs:
        family, shown = _family(cidr)
        lines.append(
            f'        {family} saddr {shown} tcp dport {int(policy.ssh_port)} '
            f'accept comment "pw:management-ssh"'
        )
    if policy.excluded_ports:
        shown = ", ".join(str(int(port)) for port in policy.excluded_ports)
        lines.append(f'        tcp dport {{ {shown} }} accept comment "pw:excluded-ports"')
    if allow_v4:
        lines.append('        ip saddr @allow_v4 accept comment "pw:allowlist"')
    if allow_v6:
        lines.append('        ip6 saddr @allow_v6 accept comment "pw:allowlist"')
    if deny_v4:
        lines.append('        ip saddr @deny_v4 drop comment "pw:denylist"')
    if deny_v6:
        lines.append('        ip6 saddr @deny_v6 drop comment "pw:denylist"')
    if ban_v4:
        lines.append('        ip saddr @ban_v4 drop comment "pw:bans"')
    if ban_v6:
        lines.append('        ip6 saddr @ban_v6 drop comment "pw:bans"')
    for rule in inbound:
        lines.append(render_named_rule(rule))
    lines.append("    }")
    if outbound:
        lines.append("    chain output {")
        lines.append("        type filter hook output priority -10; policy accept;")
        lines.append('        ct state established,related accept comment "pw:established-out"')
        for rule in outbound:
            lines.append(render_named_rule(rule))
        lines.append("    }")
    lines.append("}")
    script = "\n".join(line for line in lines if line != "") + "\n"
    assert_safe_script(script)
    return Rendered(script=script, warnings=warnings)

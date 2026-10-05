from __future__ import annotations

import ipaddress
import re
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
class GatewayPolicy:
    enabled: bool = False
    lan_ifaces: list[str] = field(default_factory=list)
    wan_iface: str = ""
    wan_backup_iface: str = ""
    active_wan: str = "primary"
    nat_enabled: bool = False
    wg_enabled: bool = False
    ips_enabled: bool = False
    ips_queue: int = 0


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
    gateway: GatewayPolicy = field(default_factory=GatewayPolicy)


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


_IFACE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,14}$")
FWMARK = "0x7077"


def validate_iface(name: str) -> str:
    cleaned = (name or "").strip()
    if not _IFACE.match(cleaned):
        raise ValueError(f"invalid interface name {name!r}")
    return cleaned


def active_wan_iface(gateway: GatewayPolicy) -> str:
    if gateway.active_wan == "backup" and gateway.wan_backup_iface:
        return gateway.wan_backup_iface
    return gateway.wan_iface


def lan_iface_names(gateway: GatewayPolicy) -> list[str]:
    names: list[str] = []
    for name in gateway.lan_ifaces:
        if name not in names:
            names.append(name)
    if gateway.wg_enabled and "wg0" not in names:
        names.append("wg0")
    return names


def _ifname(keyword: str, names: list[str]) -> str:
    cleaned = [validate_iface(name) for name in names if name]
    if not cleaned:
        return ""
    if len(cleaned) == 1:
        return f'{keyword} "{cleaned[0]}"'
    inner = ", ".join(f'"{name}"' for name in cleaned)
    return f"{keyword} {{ {inner} }}"


def _append_gateway(lines: list[str], policy: Policy, warnings: list[str]) -> None:
    gateway = policy.gateway
    if not gateway.enabled:
        return
    warnings.append(
        "Gateway mode is on. ip_forward is set to 1 only after a successful Apply, not during Preview."
    )
    lans = lan_iface_names(gateway)
    wan = active_wan_iface(gateway)
    if not lans or not wan:
        warnings.append("Gateway mode needs at least one LAN interface (or WireGuard) and a WAN interface.")
        return
    validate_iface(wan)
    forward_policy = "drop" if policy.mode == "enforce" else "accept"
    if policy.mode != "enforce":
        warnings.append("Gateway monitor mode accepts forwarded packets that no rule matches.")
    lan_match = _ifname("iifname", lans)
    wan_out = _ifname("oifname", [wan])
    wan_in = _ifname("iifname", [wan])
    lines.append("    chain forward {")
    lines.append(f"        type filter hook forward priority 0; policy {forward_policy};")
    lines.append('        ct state invalid drop comment "pw:fwd-invalid"')
    lines.append('        ct state established,related accept comment "pw:fwd-established"')
    lines.append('        meta mark 0x00000001 accept comment "pw:ips-pass"')
    lines.append(
        f'        {lan_match} {wan_out} meta mark set {FWMARK} accept comment "pw:lan-wan"'
    )
    if gateway.ips_enabled:
        lines.append(
            f'        {wan_in} ct state new queue num {int(gateway.ips_queue)} comment "pw:ips"'
        )
    else:
        lines.append(f'        {wan_in} ct state new drop comment "pw:wan-new"')
    lines.append("    }")
    if gateway.nat_enabled:
        lines.append("    chain postrouting {")
        lines.append("        type nat hook postrouting priority 100; policy accept;")
        lines.append(f'        {lan_match} {wan_out} masquerade comment "pw:nat"')
        lines.append("    }")


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
    # Dynamic probe sets: every dropped TCP/UDP dport is counted so Traffic can
    # show scan pressure without relying on host syslog mounts.
    if policy.mode == "enforce":
        for name in ("probe_tcp", "probe_udp"):
            lines.append(
                f"    set {name} {{\n"
                f"        type inet_service\n"
                f"        size 65535\n"
                f"        flags dynamic,timeout\n"
                f"        timeout 24h\n"
                f"        counter\n"
                f"    }}"
            )
    lines.append("    chain input {")
    lines.append(f"        type filter hook input priority -10; policy {policy_verdict};")
    lines.append('        ct state invalid drop comment "pw:invalid"')
    lines.append('        ct state established,related accept comment "pw:established"')
    lines.append('        iifname "lo" accept comment "pw:loopback"')
    # Host essentials. A drop policy at priority -10 would otherwise break
    # addressing, IPv6, and path MTU discovery on a normal Linux system.
    lines.append(
        '        icmp type { destination-unreachable, time-exceeded, parameter-problem } '
        'accept comment "pw:icmp-essential"'
    )
    lines.append(
        '        icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, '
        'nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, nd-redirect } '
        'accept comment "pw:icmpv6-essential"'
    )
    lines.append(
        '        icmp type echo-request limit rate 5/second accept comment "pw:ping"'
    )
    lines.append(
        '        icmpv6 type echo-request limit rate 5/second accept comment "pw:ping6"'
    )
    lines.append('        udp sport 67 udp dport 68 accept comment "pw:dhcpv4"')
    lines.append('        udp sport 547 udp dport 546 accept comment "pw:dhcpv6"')
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
    if policy.mode == "enforce":
        # Count every drop in probe_* sets, rate-limit kernel log noise, then drop.
        lines.append('        meta l4proto tcp add @probe_tcp { tcp dport } comment "pw:probe-tcp"')
        lines.append('        meta l4proto tcp limit rate 10/second log prefix "pw:drop " comment "pw:log-drop"')
        lines.append('        meta l4proto tcp drop comment "pw:drop-tcp"')
        lines.append('        meta l4proto udp add @probe_udp { udp dport } comment "pw:probe-udp"')
        lines.append('        meta l4proto udp limit rate 10/second log prefix "pw:drop " comment "pw:log-drop-udp"')
        lines.append('        meta l4proto udp drop comment "pw:drop-udp"')
        lines.append('        limit rate 5/second log prefix "pw:drop " drop comment "pw:log-drop-other"')
    lines.append("    }")
    if outbound:
        lines.append("    chain output {")
        lines.append("        type filter hook output priority -10; policy accept;")
        lines.append('        ct state established,related accept comment "pw:established-out"')
        for rule in outbound:
            lines.append(render_named_rule(rule))
        lines.append("    }")
    _append_gateway(lines, policy, warnings)
    lines.append("}")
    script = "\n".join(line for line in lines if line != "") + "\n"
    assert_safe_script(script)
    return Rendered(script=script, warnings=warnings)

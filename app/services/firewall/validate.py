from __future__ import annotations

import ipaddress
import re
from datetime import datetime

from app.timeutil import as_naive_utc, utcnow

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
COMMENT_RE = re.compile(r"^[A-Za-z0-9 _.,:/()#@+-]{0,200}$")
MAX_RULES = 500
MAX_ENTRIES = 2000
MAX_BANS = 5000


def validate_name(name: str) -> str:
    if not NAME_RE.match(name or ""):
        raise ValueError("name must be 1-64 characters: letters, digits, dot, underscore, hyphen")
    return name


def validate_comment(comment: str | None) -> str:
    text = comment or ""
    if not COMMENT_RE.match(text):
        raise ValueError("comment contains unsupported characters or is too long")
    return text


def parse_network(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError as exc:
        raise ValueError(f"invalid IP or CIDR: {value}") from exc
    return str(network)


def parse_ports(spec: str | None) -> list[str]:
    if spec is None or spec.strip() == "":
        return []
    if len(spec) > 200:
        raise ValueError("port list is too long")
    parts: list[str] = []
    for raw in spec.split(","):
        item = raw.strip()
        if not item:
            raise ValueError("empty port in list")
        if "-" in item:
            left, right = item.split("-", 1)
            try:
                start, end = int(left), int(right)
            except ValueError as exc:
                raise ValueError(f"invalid port range: {item}") from exc
            if not 1 <= start <= end <= 65535:
                raise ValueError(f"invalid port range: {item}")
            parts.append(f"{start}-{end}")
        else:
            try:
                port = int(item)
            except ValueError as exc:
                raise ValueError(f"invalid port: {item}") from exc
            if not 1 <= port <= 65535:
                raise ValueError(f"invalid port: {item}")
            parts.append(str(port))
        if len(parts) > 32:
            raise ValueError("too many ports")
    return parts


def validate_priority(priority: int) -> int:
    if not isinstance(priority, int) or isinstance(priority, bool) or not 0 <= priority <= 10000:
        raise ValueError("priority must be an integer from 0 to 10000")
    return priority


def validate_expiry(expires_at: datetime | None, *, allow_past: bool = False) -> datetime | None:
    expires_at = as_naive_utc(expires_at)
    if expires_at is not None and not allow_past and expires_at <= utcnow():
        raise ValueError("expiration must be in the future")
    return expires_at


def assert_rule_scope(protocol: str, src: str | None, dst: str | None, ports: str | None) -> None:
    has_addr = bool(src or dst)
    parsed_ports = parse_ports(ports)
    if protocol == "any" and not has_addr:
        raise ValueError("rule matches all traffic; set a source, destination, or choose a protocol and port")
    if protocol in {"tcp", "udp"} and not parsed_ports and not has_addr:
        raise ValueError("rule matches every port; set ports or an address")


def network_of(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValueError(f"invalid IP or CIDR: {value}") from exc


def contains_protected(candidate: str, protected: list[str]) -> bool:
    """True when candidate contains a protected network (would swallow it)."""
    net = network_of(candidate)
    for item in protected:
        other = network_of(item)
        if net.version != other.version:
            continue
        if other.subnet_of(net):
            return True
    return False


def overlaps(left: str, right: str) -> bool:
    a = network_of(left)
    b = network_of(right)
    if a.version != b.version:
        return False
    return a.overlaps(b)


def assert_ban_width(cidr: str) -> str:
    normalized = parse_network(cidr)
    if normalized is None:
        raise ValueError("ban target is required")
    net = network_of(normalized)
    minimum = 24 if net.version == 4 else 64
    if net.prefixlen < minimum:
        raise ValueError(f"ban target is too broad; use a /{minimum} or smaller range")
    return normalized

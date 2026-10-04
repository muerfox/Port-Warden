from __future__ import annotations

from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import Settings
from app.models import Ban, IpList, IpListEntry, Rule
from app.services.firewall.engine import FirewallEngine, get_setting, script_sha, set_setting
from app.services.firewall.validate import (
    MAX_BANS,
    MAX_ENTRIES,
    MAX_RULES,
    assert_ban_width,
    assert_rule_scope,
    contains_protected,
    overlaps,
    parse_network,
    parse_ports,
    validate_comment,
    validate_expiry,
    validate_name,
    validate_priority,
)
from app.timeutil import is_expired, utcnow


def _protected(settings: Settings) -> list[str]:
    return list(settings.management_cidrs)


def _cidrs(db: Session, kind: str) -> list[str]:
    rows = db.scalars(select(IpList).where(IpList.kind == kind)).all()
    found: list[str] = []
    for ip_list in rows:
        entries = db.scalars(select(IpListEntry).where(IpListEntry.list_id == ip_list.id)).all()
        for entry in entries:
            if not is_expired(entry.expires_at):
                found.append(entry.cidr)
    return found


def rule_from_payload(data: dict, *, allow_past: bool = False) -> dict:
    name = validate_name(data["name"])
    action = data["action"]
    direction = data["direction"]
    protocol = data["protocol"]
    if action not in {"allow", "deny"} or direction not in {"in", "out"} or protocol not in {"tcp", "udp", "icmp", "any"}:
        raise ValueError("invalid rule action, direction, or protocol")
    src = parse_network(data.get("src_cidr"))
    dst = parse_network(data.get("dst_cidr"))
    ports = data.get("ports") or None
    if isinstance(ports, str):
        ports = ports.strip() or None
    parse_ports(ports)
    assert_rule_scope(protocol, src, dst, ports)
    return {
        "name": name,
        "action": action,
        "direction": direction,
        "protocol": protocol,
        "src_cidr": src,
        "dst_cidr": dst,
        "ports": ports,
        "comment": validate_comment(data.get("comment")),
        "priority": validate_priority(int(data.get("priority", 100))),
        "enabled": bool(data.get("enabled", True)),
        "expires_at": validate_expiry(data.get("expires_at"), allow_past=allow_past),
    }


def create_rule(db: Session, data: dict) -> Rule:
    if (db.scalar(select(func.count()).select_from(Rule)) or 0) >= MAX_RULES:
        raise ValueError("rule limit reached")
    fields = rule_from_payload(data)
    if db.scalar(select(Rule).where(Rule.name == fields["name"])):
        raise ValueError("a rule with that name already exists")
    now = utcnow()
    row = Rule(created_at=now, updated_at=now, **fields)
    db.add(row)
    db.flush()
    return row


def update_rule(db: Session, row: Rule, data: dict) -> Rule:
    merged = {
        "name": data.get("name", row.name),
        "action": data.get("action", row.action),
        "direction": data.get("direction", row.direction),
        "protocol": data.get("protocol", row.protocol),
        "src_cidr": row.src_cidr if "src_cidr" not in data else data.get("src_cidr"),
        "dst_cidr": row.dst_cidr if "dst_cidr" not in data else data.get("dst_cidr"),
        "ports": row.ports if "ports" not in data else data.get("ports"),
        "comment": row.comment if data.get("comment") is None else data.get("comment"),
        "priority": row.priority if data.get("priority") is None else data.get("priority"),
        "enabled": row.enabled if data.get("enabled") is None else data.get("enabled"),
        "expires_at": row.expires_at if "expires_at" not in data else data.get("expires_at"),
    }
    fields = rule_from_payload(merged, allow_past=True)
    other = db.scalar(select(Rule).where(Rule.name == fields["name"], Rule.id != row.id))
    if other is not None:
        raise ValueError("a rule with that name already exists")
    for key, value in fields.items():
        setattr(row, key, value)
    row.updated_at = utcnow()
    db.flush()
    return row


def create_list(db: Session, name: str, kind: str, comment: str) -> IpList:
    if kind not in {"allow", "deny"}:
        raise ValueError("list kind must be allow or deny")
    name = validate_name(name)
    if db.scalar(select(IpList).where(IpList.name == name)):
        raise ValueError("a list with that name already exists")
    row = IpList(name=name, kind=kind, comment=validate_comment(comment), builtin=False)
    db.add(row)
    db.flush()
    return row


def add_entry(db: Session, ip_list: IpList, cidr: str, comment: str, expires_at, settings: Settings) -> IpListEntry:
    count = db.scalar(select(func.count()).select_from(IpListEntry).where(IpListEntry.list_id == ip_list.id)) or 0
    if count >= MAX_ENTRIES:
        raise ValueError("list entry limit reached")
    normalized = parse_network(cidr)
    if normalized is None:
        raise ValueError("CIDR is required")
    if db.scalar(select(IpListEntry).where(IpListEntry.list_id == ip_list.id, IpListEntry.cidr == normalized)):
        raise ValueError("that CIDR is already on this list")
    protected = _protected(settings)
    opposite = _cidrs(db, "deny" if ip_list.kind == "allow" else "allow")
    if ip_list.kind == "deny" and contains_protected(normalized, protected):
        raise ValueError("denylist entry would include a management CIDR")
    for other in opposite:
        if overlaps(normalized, other):
            raise ValueError("entry overlaps the opposite list")
    if ip_list.kind == "allow":
        for other in _cidrs(db, "deny"):
            if overlaps(normalized, other):
                raise ValueError("allowlist entry overlaps the denylist")
    row = IpListEntry(
        list_id=ip_list.id,
        cidr=normalized,
        comment=validate_comment(comment),
        expires_at=validate_expiry(expires_at),
        created_at=utcnow(),
    )
    db.add(row)
    db.flush()
    return row


def _ban_active(ban: Ban, now) -> bool:
    return ban.lifted_at is None and (ban.permanent or not is_expired(ban.expires_at, now))


def assert_ban_allowed(db: Session, cidr: str, settings: Settings) -> str:
    normalized = assert_ban_width(cidr)
    if contains_protected(normalized, _protected(settings)) or contains_protected(normalized, _cidrs(db, "allow")):
        raise ValueError("that address is protected by a management CIDR or the allowlist")
    return normalized


def create_ban(
    db: Session,
    settings: Settings,
    engine: FirewallEngine,
    *,
    ip: str,
    reason: str,
    source: str,
    permanent: bool,
    seconds: int | None,
) -> Ban:
    if (db.scalar(select(func.count()).select_from(Ban).where(Ban.lifted_at.is_(None))) or 0) >= MAX_BANS:
        raise ValueError("ban limit reached")
    normalized = assert_ban_allowed(db, ip, settings)
    now = utcnow()
    for existing in db.scalars(select(Ban).where(Ban.ip == normalized, Ban.lifted_at.is_(None))).all():
        if _ban_active(existing, now):
            raise ValueError("that address is already banned")
    if permanent:
        expires = None
    else:
        duration = seconds if seconds is not None else settings.bf_ban_seconds
        if not 60 <= int(duration) <= 31_536_000:
            raise ValueError("ban duration must be between 60 and 31536000 seconds")
        expires = now + timedelta(seconds=int(duration))
    previous = script_sha(engine.render(db).script)
    row = Ban(
        ip=normalized,
        reason=validate_comment(reason) or source,
        source=source,
        permanent=permanent,
        expires_at=expires,
        created_at=now,
        lifted_at=None,
    )
    db.add(row)
    db.flush()
    engine.maybe_auto_apply(db, previous)
    return row


def lift_ban(db: Session, engine: FirewallEngine, ban: Ban) -> Ban:
    if ban.lifted_at is not None:
        raise ValueError("ban is already lifted")
    previous = script_sha(engine.render(db).script)
    ban.lifted_at = utcnow()
    db.flush()
    engine.maybe_auto_apply(db, previous)
    return ban


def bf_config(db: Session, settings: Settings) -> dict:
    def value(key: str, default: int) -> int:
        raw = get_setting(db, key)
        return int(raw) if raw is not None else default

    return {
        "threshold": value("bf_threshold", settings.bf_threshold),
        "window_seconds": value("bf_window_seconds", settings.bf_window_seconds),
        "ban_seconds": value("bf_ban_seconds", settings.bf_ban_seconds),
        "cooldown_seconds": value("bf_cooldown_seconds", settings.bf_cooldown_seconds),
        "permanent_after": value("bf_permanent_after", settings.bf_permanent_after),
    }


def save_bf_config_fields(db: Session, payload: dict) -> None:
    mapping = {
        "bf_threshold": payload["threshold"],
        "bf_window_seconds": payload["window_seconds"],
        "bf_ban_seconds": payload["ban_seconds"],
        "bf_cooldown_seconds": payload["cooldown_seconds"],
        "bf_permanent_after": payload["permanent_after"],
    }
    for key, value in mapping.items():
        set_setting(db, key, str(int(value)))

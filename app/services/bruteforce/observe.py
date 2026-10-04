from __future__ import annotations

import ipaddress
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings
from app.logging_json import JsonLogger
from app.models import Ban
from app.services.bruteforce.parser import parse_auth_line
from app.services.bruteforce.tracker import FailureTracker
from app.services.events import record_event
from app.services.firewall.engine import FirewallEngine
from app.services.records import _cidrs, assert_ban_allowed, bf_config, create_ban
from app.timeutil import is_expired, utcnow


def _in_cidrs(ip: str, cidrs: list[str]) -> bool:
    addr = ipaddress.ip_address(ip)
    for cidr in cidrs:
        network = ipaddress.ip_network(cidr, strict=False)
        if addr.version == network.version and addr in network:
            return True
    return False


def _covers(stored: str, ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(stored, strict=False)
    except ValueError:
        return False


def _active_ban(db: Session, ip: str, now):
    rows = db.scalars(select(Ban).where(Ban.lifted_at.is_(None)).order_by(Ban.id.desc())).all()
    for ban in rows:
        if not _covers(ban.ip, ip):
            continue
        if ban.permanent or not is_expired(ban.expires_at, now):
            return ban
    return None


def _cooling(db: Session, ip: str, now, cooldown_seconds: int) -> bool:
    rows = db.scalars(select(Ban).order_by(Ban.id.desc())).all()
    latest = next((ban for ban in rows if _covers(ban.ip, ip)), None)
    if latest is None:
        return False
    if latest.lifted_at is None and (latest.permanent or not is_expired(latest.expires_at, now)):
        return True
    end = latest.lifted_at or latest.expires_at
    if end is None:
        return False
    return now < end + timedelta(seconds=cooldown_seconds)


def observe_ip(
    db: Session,
    tracker: FailureTracker,
    settings: Settings,
    engine: FirewallEngine,
    logger: JsonLogger,
    ip: str,
    reason: str,
    *,
    now=None,
) -> dict:
    now = now or utcnow()
    config = bf_config(db, settings)
    if _in_cidrs(ip, settings.management_cidrs) or _in_cidrs(ip, _cidrs(db, "allow")):
        record_event(db, logger, "auth_failure", src_ip=ip, action="ignored_allowlist", details={"reason": reason})
        return {"src_ip": ip, "action": "ignored_allowlist", "reason": reason}

    if _active_ban(db, ip, now) is not None or _cooling(db, ip, now, config["cooldown_seconds"]):
        record_event(db, logger, "auth_failure", src_ip=ip, action="cooldown", details={"reason": reason})
        return {"src_ip": ip, "action": "cooldown", "reason": reason}

    count = tracker.add(ip, now, config["window_seconds"])
    record_event(
        db,
        logger,
        "auth_failure",
        src_ip=ip,
        action=reason,
        details={"count": count, "threshold": config["threshold"]},
    )
    if count < config["threshold"]:
        return {"src_ip": ip, "action": "count", "count": count, "reason": reason}

    prior = sum(1 for ban in db.scalars(select(Ban)).all() if _covers(ban.ip, ip))
    permanent = config["permanent_after"] > 0 and prior + 1 >= config["permanent_after"]
    try:
        assert_ban_allowed(db, ip, settings)
    except ValueError:
        return {"src_ip": ip, "action": "ignored_allowlist", "reason": reason}

    ban = create_ban(
        db,
        settings,
        engine,
        ip=ip,
        reason=reason,
        source="bruteforce",
        permanent=permanent,
        seconds=None if permanent else config["ban_seconds"],
    )
    tracker.clear(ip)
    record_event(
        db,
        logger,
        "ban",
        src_ip=ip,
        action="ban",
        rule_id=str(ban.id),
        details={"permanent": permanent, "source": "bruteforce"},
    )
    return {
        "src_ip": ip,
        "action": "ban",
        "ban_id": ban.id,
        "permanent": permanent,
        "count": count,
        "reason": reason,
    }


def observe_line(
    db: Session,
    tracker: FailureTracker,
    settings: Settings,
    engine: FirewallEngine,
    logger: JsonLogger,
    line: str,
) -> dict | None:
    parsed = parse_auth_line(line)
    if parsed is None:
        return None
    return observe_ip(
        db,
        tracker,
        settings,
        engine,
        logger,
        parsed["src_ip"],
        parsed["reason"],
    )

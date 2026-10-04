from __future__ import annotations

import json
from datetime import timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.logging_json import REDACT_KEYS, JsonLogger
from app.models import AuditLog, Event
from app.timeutil import iso, utcnow


def _clean(details: dict | None) -> dict:
    if not details:
        return {}
    return {key: value for key, value in details.items() if key.lower() not in REDACT_KEYS}


def record_event(
    db: Session,
    logger: JsonLogger,
    event_type: str,
    *,
    src_ip: str = "",
    dst_port: int | None = None,
    action: str = "",
    rule_id: str = "",
    details: dict | None = None,
) -> None:
    clean = _clean(details)
    db.add(
        Event(
            timestamp=utcnow(),
            event_type=event_type,
            src_ip=src_ip or "",
            dst_port=dst_port,
            action=action,
            rule_id=rule_id or "",
            details=json.dumps(clean, default=str, separators=(",", ":")),
        )
    )
    logger.emit(
        event_type,
        src_ip=src_ip or "",
        dst_port=dst_port if dst_port is not None else "",
        action=action,
        rule_id=rule_id or "",
        details=clean,
    )


def record_audit(
    db: Session,
    logger: JsonLogger,
    *,
    actor: str,
    action: str,
    target: str,
    src_ip: str,
    details: dict | None = None,
) -> None:
    clean = _clean(details)
    db.add(
        AuditLog(
            timestamp=utcnow(),
            actor=actor,
            action=action,
            target=target,
            src_ip=src_ip or "",
            details=json.dumps(clean, default=str, separators=(",", ":")),
        )
    )
    record_event(
        db,
        logger,
        "audit",
        src_ip=src_ip,
        action=action,
        rule_id=target,
        details={"actor": actor, **clean},
    )


def event_dict(row: Event) -> dict:
    return {
        "id": row.id,
        "timestamp": iso(row.timestamp),
        "event_type": row.event_type,
        "src_ip": row.src_ip,
        "dst_port": row.dst_port,
        "action": row.action,
        "rule_id": row.rule_id,
        "details": row.details,
    }


def audit_dict(row: AuditLog) -> dict:
    return {
        "id": row.id,
        "timestamp": iso(row.timestamp),
        "actor": row.actor,
        "action": row.action,
        "target": row.target,
        "src_ip": row.src_ip,
        "details": row.details,
    }


def purge_records(db: Session, retention_days: int) -> None:
    cutoff = utcnow() - timedelta(days=retention_days)
    db.execute(delete(Event).where(Event.timestamp < cutoff))
    db.execute(delete(AuditLog).where(AuditLog.timestamp < cutoff))


def count_events(db: Session) -> int:
    return int(db.scalar(select(func.count()).select_from(Event)) or 0)

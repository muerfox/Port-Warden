from __future__ import annotations

from app.models import Ban, Honeypot, IpList, IpListEntry, Rule
from app.timeutil import iso


def rule_dict(row: Rule) -> dict:
    return {
        "id": row.id,
        "name": row.name,
        "action": row.action,
        "direction": row.direction,
        "protocol": row.protocol,
        "src_cidr": row.src_cidr,
        "dst_cidr": row.dst_cidr,
        "ports": row.ports,
        "comment": row.comment,
        "priority": row.priority,
        "enabled": row.enabled,
        "expires_at": iso(row.expires_at),
        "created_at": iso(row.created_at),
        "updated_at": iso(row.updated_at),
    }


def entry_dict(row: IpListEntry) -> dict:
    return {
        "id": row.id,
        "list_id": row.list_id,
        "cidr": row.cidr,
        "comment": row.comment,
        "expires_at": iso(row.expires_at),
        "created_at": iso(row.created_at),
    }


def list_dict(row: IpList, entries: list[IpListEntry]) -> dict:
    return {
        "id": row.id,
        "name": row.name,
        "kind": row.kind,
        "comment": row.comment,
        "builtin": row.builtin,
        "entries": [entry_dict(entry) for entry in entries],
    }


def ban_dict(row: Ban) -> dict:
    return {
        "id": row.id,
        "ip": row.ip,
        "reason": row.reason,
        "source": row.source,
        "permanent": row.permanent,
        "expires_at": iso(row.expires_at),
        "created_at": iso(row.created_at),
        "lifted_at": iso(row.lifted_at),
        "active": row.lifted_at is None,
    }


def honeypot_dict(row: Honeypot) -> dict:
    return {
        "name": row.name,
        "kind": row.kind,
        "listen_port": row.listen_port,
        "enabled": row.enabled,
        "note": row.note,
        "label": "decoy / monitoring only",
    }

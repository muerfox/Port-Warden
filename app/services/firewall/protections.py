from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Rule
from app.services.records import create_rule

# Opt-in deny packs. Enabling writes desired rules; Firewall Apply still required.
# Priority 20 runs early among named rules (before typical allow rules at 100).

PROTECTION_PACKS: list[dict] = [
    {
        "id": "legacy-remote",
        "title": "Legacy remote admin",
        "summary": "Deny inbound Telnet, FTP, SMB/NetBIOS, RDP, and VNC.",
        "recommended": True,
        "rules": [
            {
                "name": "protect-legacy-remote",
                "action": "deny",
                "direction": "in",
                "protocol": "tcp",
                "ports": "21,23,135,139,445,3389,5900",
                "comment": "Protect: Telnet FTP SMB RDP VNC",
                "priority": 20,
            },
        ],
    },
    {
        "id": "databases",
        "title": "Database and cache ports",
        "summary": "Deny inbound MySQL, PostgreSQL, MSSQL, MongoDB, Redis, Memcached, and Elasticsearch.",
        "recommended": True,
        "rules": [
            {
                "name": "protect-databases",
                "action": "deny",
                "direction": "in",
                "protocol": "tcp",
                "ports": "1433,3306,5432,6379,9200,11211,27017",
                "comment": "Protect: SQL and cache services",
                "priority": 20,
            },
        ],
    },
    {
        "id": "mail",
        "title": "Mail protocols",
        "summary": "Deny inbound SMTP, submission, IMAP, and POP3. Enable only if this host is not a mail server.",
        "recommended": True,
        "rules": [
            {
                "name": "protect-mail",
                "action": "deny",
                "direction": "in",
                "protocol": "tcp",
                "ports": "25,110,143,465,587,993,995",
                "comment": "Protect: SMTP IMAP POP3",
                "priority": 20,
            },
        ],
    },
    {
        "id": "ssh-default-22",
        "title": "Block default SSH port 22",
        "summary": "Deny inbound TCP/22. Use when sshd listens elsewhere (for example 2222) so scanners hitting 22 are dropped.",
        "recommended": False,
        "rules": [
            {
                "name": "protect-ssh-22",
                "action": "deny",
                "direction": "in",
                "protocol": "tcp",
                "ports": "22",
                "comment": "Protect: default SSH port",
                "priority": 20,
            },
        ],
    },
    {
        "id": "remote-apis",
        "title": "Exposed management APIs",
        "summary": "Deny inbound Docker API, Kubernetes kubelet, etcd, and common unauthenticated admin UIs.",
        "recommended": True,
        "rules": [
            {
                "name": "protect-remote-apis",
                "action": "deny",
                "direction": "in",
                "protocol": "tcp",
                "ports": "2375,2376,2379,2380,6443,10250,5601,8161,9000",
                "comment": "Protect: Docker K8s admin APIs",
                "priority": 20,
            },
        ],
    },
    {
        "id": "ldap-directory",
        "title": "Directory services",
        "summary": "Deny inbound LDAP and LDAPS from the network edge.",
        "recommended": False,
        "rules": [
            {
                "name": "protect-ldap",
                "action": "deny",
                "direction": "in",
                "protocol": "tcp",
                "ports": "389,636",
                "comment": "Protect: LDAP",
                "priority": 20,
            },
        ],
    },
    {
        "id": "rpc-nfs",
        "title": "RPC and NFS",
        "summary": "Deny inbound sunrpc and NFS ports commonly abused on internet-facing hosts.",
        "recommended": True,
        "rules": [
            {
                "name": "protect-rpc-nfs",
                "action": "deny",
                "direction": "in",
                "protocol": "tcp",
                "ports": "111,2049",
                "comment": "Protect: RPC NFS TCP",
                "priority": 20,
            },
            {
                "name": "protect-rpc-nfs-udp",
                "action": "deny",
                "direction": "in",
                "protocol": "udp",
                "ports": "111,2049",
                "comment": "Protect: RPC NFS UDP",
                "priority": 20,
            },
        ],
    },
]


def get_pack(pack_id: str) -> dict | None:
    for pack in PROTECTION_PACKS:
        if pack["id"] == pack_id:
            return dict(pack)
    return None


def pack_rule_names(pack: dict) -> list[str]:
    return [str(rule["name"]) for rule in pack.get("rules", [])]


def pack_status(db: Session, pack: dict) -> dict:
    names = pack_rule_names(pack)
    existing = {
        row.name: row
        for row in db.scalars(select(Rule).where(Rule.name.in_(names))).all()
    }
    present = [name for name in names if name in existing]
    enabled = bool(names) and len(present) == len(names)
    return {
        "id": pack["id"],
        "title": pack["title"],
        "summary": pack["summary"],
        "recommended": bool(pack.get("recommended")),
        "enabled": enabled,
        "rule_names": names,
        "present_rules": present,
        "missing_rules": [name for name in names if name not in existing],
    }


def list_protection_status(db: Session) -> list[dict]:
    return [pack_status(db, pack) for pack in PROTECTION_PACKS]


def enable_protection(db: Session, pack_id: str) -> dict:
    pack = get_pack(pack_id)
    if pack is None:
        raise ValueError("unknown protection pack")
    created = []
    skipped = []
    for rule in pack["rules"]:
        if db.scalar(select(Rule).where(Rule.name == rule["name"])):
            skipped.append(rule["name"])
            continue
        create_rule(
            db,
            {
                "name": rule["name"],
                "action": rule["action"],
                "direction": rule["direction"],
                "protocol": rule["protocol"],
                "ports": rule.get("ports"),
                "src_cidr": rule.get("src_cidr"),
                "dst_cidr": rule.get("dst_cidr"),
                "comment": rule.get("comment", ""),
                "priority": int(rule.get("priority", 20)),
                "enabled": True,
            },
        )
        created.append(rule["name"])
    return {"pack": pack_id, "created": created, "skipped": skipped, **pack_status(db, pack)}


def disable_protection(db: Session, pack_id: str) -> dict:
    pack = get_pack(pack_id)
    if pack is None:
        raise ValueError("unknown protection pack")
    removed = []
    for name in pack_rule_names(pack):
        row = db.scalar(select(Rule).where(Rule.name == name))
        if row is None:
            continue
        db.delete(row)
        removed.append(name)
    db.flush()
    return {"pack": pack_id, "removed": removed, **pack_status(db, pack)}


def enable_recommended(db: Session) -> dict:
    results = []
    for pack in PROTECTION_PACKS:
        if pack.get("recommended"):
            results.append(enable_protection(db, pack["id"]))
    return {"enabled": results, "packs": list_protection_status(db)}

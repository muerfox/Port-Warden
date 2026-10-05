from __future__ import annotations

import ipaddress
import json
import subprocess

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Event, WgPeer
from app.services.firewall.engine import get_setting, set_setting
from app.services.firewall.render import GatewayPolicy, active_wan_iface, validate_iface
from app.timeutil import utcnow

WG_IFACE = "wg0"
ROUTE_TABLE = "77"
FWMARK = "0x7077"


def _flag(db: Session, key: str) -> bool:
    return (get_setting(db, key, "0") or "0") == "1"


def _text(db: Session, key: str, default: str = "") -> str:
    return get_setting(db, key, default) or default


def load_gateway(db: Session) -> GatewayPolicy:
    lans: list[str] = []
    for part in _text(db, "lan_ifaces").split(","):
        name = part.strip()
        if not name:
            continue
        try:
            cleaned = validate_iface(name)
        except ValueError:
            continue
        if cleaned not in lans:
            lans.append(cleaned)
    wan = _text(db, "wan_iface")
    backup = _text(db, "wan_backup_iface")
    try:
        wan = validate_iface(wan) if wan else ""
    except ValueError:
        wan = ""
    try:
        backup = validate_iface(backup) if backup else ""
    except ValueError:
        backup = ""
    active = _text(db, "active_wan", "primary")
    if active not in {"primary", "backup"}:
        active = "primary"
    try:
        queue = int(_text(db, "ips_queue", "0") or "0")
    except ValueError:
        queue = 0
    return GatewayPolicy(
        enabled=_flag(db, "gateway_enabled"),
        lan_ifaces=lans,
        wan_iface=wan,
        wan_backup_iface=backup,
        active_wan=active,
        nat_enabled=_flag(db, "nat_enabled"),
        wg_enabled=_flag(db, "wg_enabled"),
        ips_enabled=_flag(db, "ips_enabled"),
        ips_queue=0 if queue != 0 else 0,
    )


def save_gateway(
    db: Session,
    *,
    enabled: bool,
    lan_ifaces: list[str],
    wan_iface: str,
    wan_backup_iface: str,
    nat_enabled: bool,
    wg_enabled: bool,
    wg_port: int,
    wg_address: str,
    ips_enabled: bool,
    wan_gateway: str,
    wan_backup_gateway: str,
) -> None:
    lans = []
    for name in lan_ifaces:
        cleaned = validate_iface(name)
        if cleaned == WG_IFACE:
            continue
        if cleaned not in lans:
            lans.append(cleaned)
    wan = validate_iface(wan_iface) if wan_iface else ""
    backup = validate_iface(wan_backup_iface) if wan_backup_iface else ""
    if wan and wan in lans:
        raise ValueError("WAN interface cannot also be a LAN interface")
    if backup and backup in lans:
        raise ValueError("Backup WAN interface cannot also be a LAN interface")
    if backup and backup == wan:
        raise ValueError("Backup WAN must be a different interface")
    if not 1 <= int(wg_port) <= 65535:
        raise ValueError("WireGuard port out of range")
    address = ipaddress.ip_interface(wg_address)
    if address.version != 4:
        raise ValueError("WireGuard address must be an IPv4 interface address")
    for label, value in (("WAN gateway", wan_gateway), ("backup WAN gateway", wan_backup_gateway)):
        if not value:
            continue
        ipaddress.ip_address(value)
        if any(char.isalpha() for char in value):
            raise ValueError(f"{label} must be an IP address, not a hostname")
    set_setting(db, "gateway_enabled", "1" if enabled else "0")
    set_setting(db, "lan_ifaces", ",".join(lans))
    set_setting(db, "wan_iface", wan)
    set_setting(db, "wan_backup_iface", backup)
    set_setting(db, "nat_enabled", "1" if nat_enabled else "0")
    set_setting(db, "wg_enabled", "1" if wg_enabled else "0")
    set_setting(db, "wg_port", str(int(wg_port)))
    set_setting(db, "wg_address", str(address))
    set_setting(db, "ips_enabled", "1" if ips_enabled else "0")
    set_setting(db, "ips_queue", "0")
    set_setting(db, "wan_gateway", wan_gateway.strip())
    set_setting(db, "wan_backup_gateway", wan_backup_gateway.strip())
    if not backup:
        set_setting(db, "active_wan", "primary")


def gateway_view(db: Session) -> dict:
    gateway = load_gateway(db)
    peers = db.scalars(select(WgPeer).order_by(WgPeer.id)).all()
    since = utcnow().replace(microsecond=0)
    from datetime import timedelta

    cutoff = since - timedelta(hours=24)
    alerts = int(
        db.scalar(
            select(func.count()).select_from(Event).where(Event.event_type == "ips_alert").where(Event.timestamp >= cutoff)
        )
        or 0
    )
    return {
        "enabled": gateway.enabled,
        "lan_ifaces": gateway.lan_ifaces,
        "wan_iface": gateway.wan_iface,
        "wan_backup_iface": gateway.wan_backup_iface,
        "active_wan": gateway.active_wan,
        "active_iface": active_wan_iface(gateway) if gateway.enabled else "",
        "nat_enabled": gateway.nat_enabled,
        "wg_enabled": gateway.wg_enabled,
        "wg_port": _text(db, "wg_port", "51820"),
        "wg_address": _text(db, "wg_address", "10.77.0.1/24"),
        "ips_enabled": gateway.ips_enabled,
        "wan_gateway": _text(db, "wan_gateway"),
        "wan_backup_gateway": _text(db, "wan_backup_gateway"),
        "peers": peers,
        "peer_count": len(peers),
        "ips_alerts_24h": alerts,
    }


def list_interfaces(ip_bin: str = "ip") -> list[str]:
    try:
        completed = subprocess.run(
            [ip_bin, "-j", "link"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if completed.returncode != 0 or not completed.stdout.strip():
        return []
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return []
    names = []
    for item in payload:
        name = str(item.get("ifname", "")).strip()
        if not name:
            continue
        try:
            names.append(validate_iface(name))
        except ValueError:
            continue
    return names

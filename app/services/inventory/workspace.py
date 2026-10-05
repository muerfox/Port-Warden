from __future__ import annotations

from sqlalchemy.orm import Session

from app.config import Settings, _port_list
from app.services.firewall.engine import get_setting, set_setting
from app.services.inventory.ports import detect_ssh_ports, read_host_listeners

OPEN_PORTS_KEY = "open_ports"
SSH_PORT_KEY = "ssh_port"


def effective_ssh_port(db: Session, settings: Settings, listeners: list[dict] | None = None) -> int:
    """Prefer live sshd detection; fall back to stored/env defaults."""
    detected = detect_ssh_ports(listeners)
    if detected:
        preferred = int(settings.ssh_port)
        if preferred in detected:
            return preferred
        return int(detected[0])
    raw = get_setting(db, SSH_PORT_KEY)
    if raw and str(raw).strip().isdigit():
        port = int(str(raw).strip())
        if 1 <= port <= 65535:
            return port
    return int(settings.ssh_port)


def effective_open_ports(db: Session, settings: Settings) -> list[int]:
    """Operator-chosen open ports from the panel, plus the UI bind port."""
    raw = get_setting(db, OPEN_PORTS_KEY)
    if raw is None:
        # First run only: optional env seed. Empty means discover, then choose in the panel.
        ports = set(int(port) for port in settings.excluded_ports)
    else:
        ports = set(_port_list(raw))
    ports.add(int(settings.bind_port))
    return sorted(port for port in ports if 1 <= int(port) <= 65535)


def save_open_ports(db: Session, ports: list[int]) -> list[int]:
    cleaned = sorted({int(port) for port in ports if 1 <= int(port) <= 65535})
    set_setting(db, OPEN_PORTS_KEY, ",".join(str(port) for port in cleaned))
    return cleaned


def keep_port_open(db: Session, settings: Settings, port: int) -> list[int]:
    port = int(port)
    if not 1 <= port <= 65535:
        raise ValueError("port out of range")
    current = set(effective_open_ports(db, settings))
    current.add(port)
    return save_open_ports(db, sorted(current))


def close_port(db: Session, settings: Settings, port: int) -> list[int]:
    port = int(port)
    if port == int(settings.bind_port):
        raise ValueError("the UI bind port stays open so the panel remains reachable")
    current = set(effective_open_ports(db, settings))
    current.discard(port)
    return save_open_ports(db, sorted(current))


def consolidate_listeners(rows: list[dict]) -> list[dict]:
    grouped: dict[tuple[str, int], dict] = {}
    for row in rows:
        key = (row["protocol"], int(row["port"]))
        item = grouped.get(key)
        if item is None:
            grouped[key] = {
                "protocol": row["protocol"],
                "port": int(row["port"]),
                "addresses": [row["address"]],
                "scope": row["scope"],
                "scope_label": row["scope_label"],
                "possibly_public": bool(row["possibly_public"]),
                "process": row.get("process") or "",
                "pid": row.get("pid"),
                "service": row.get("service") or "unknown",
                "is_ssh": bool(row.get("is_ssh")),
            }
            continue
        if row["address"] not in item["addresses"]:
            item["addresses"].append(row["address"])
        item["possibly_public"] = item["possibly_public"] or bool(row["possibly_public"])
        rank = {"local": 0, "private_interface": 1, "public_address": 2, "all_interfaces": 3}
        if rank.get(row["scope"], 0) > rank.get(item["scope"], 0):
            item["scope"] = row["scope"]
            item["scope_label"] = row["scope_label"]
        if not item["process"] and row.get("process"):
            item["process"] = row["process"]
            item["pid"] = row.get("pid")
            item["service"] = row.get("service") or item["service"]
            item["is_ssh"] = bool(row.get("is_ssh"))
        elif row.get("is_ssh"):
            item["is_ssh"] = True
            item["service"] = "SSH"
    return sorted(
        grouped.values(),
        key=lambda row: (0 if row["possibly_public"] else 1, row["port"], row["protocol"]),
    )


def panel_rows(db: Session, settings: Settings) -> list[dict]:
    listeners = read_host_listeners()
    open_ports = set(effective_open_ports(db, settings))
    ssh_port = effective_ssh_port(db, settings, listeners)
    bind = int(settings.bind_port)
    rows = []
    for item in consolidate_listeners(listeners):
        port = int(item["port"])
        kept = port in open_ports
        process = item.get("process") or ""
        pid = item.get("pid")
        service = item.get("service") or "unknown"
        if port == bind:
            status = "UI panel (always open)"
            if not process:
                process = "port-warden"
                service = "Port Warden UI"
        elif item.get("is_ssh") or port == ssh_port:
            status = "SSH (auto-detected)" if item.get("is_ssh") else "management SSH"
            service = "SSH"
        elif kept:
            status = "kept open"
        else:
            status = "will drop in enforce"
        process_text = process or "unknown"
        if pid:
            process_text = f"{process_text} (pid {pid})"
        rows.append(
            {
                **item,
                "address_text": ", ".join(item["addresses"]),
                "process_text": process_text,
                "service": service,
                "is_open": kept,
                "is_ssh": bool(item.get("is_ssh")) or port == ssh_port,
                "is_ui": port == bind,
                "status": status,
            }
        )
    return rows

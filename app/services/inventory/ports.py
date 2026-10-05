from __future__ import annotations

import ipaddress
import socket
import subprocess
from pathlib import Path

CLASS_LABELS = {
    "local": "Listening locally",
    "private_interface": "Listening on a private address",
    "all_interfaces": "Listening on all interfaces",
    "public_address": "Bound to a public address",
}

REACHABILITY_NOTE = (
    "A listening socket is not proof that the public internet can connect. "
    "Routers, NAT, cloud security groups, and upstream firewalls can block or expose the port."
)


def classify_address(address: str) -> str:
    if address in {"0.0.0.0", "::", "*"}:
        return "all_interfaces"
    ip = ipaddress.ip_address(address)
    if ip.is_loopback:
        return "local"
    if ip.is_private or ip.is_link_local:
        return "private_interface"
    return "public_address"


def _row(protocol: str, address: str, port: int) -> dict:
    kind = classify_address(address)
    return {
        "protocol": protocol,
        "address": address,
        "port": port,
        "scope": kind,
        "scope_label": CLASS_LABELS[kind],
        "possibly_public": kind in {"all_interfaces", "public_address"},
    }


def split_host_port(value: str) -> tuple[str, int]:
    if value.startswith("["):
        host, _, port = value[1:].rpartition("]:")
        return host, int(port)
    host, _, port = value.rpartition(":")
    return host, int(port)


def parse_ss(text: str) -> list[dict]:
    rows = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        protocol, state = parts[0], parts[1]
        if protocol not in {"tcp", "udp"}:
            continue
        if protocol == "tcp" and state != "LISTEN":
            continue
        if protocol == "udp" and state not in {"UNCONN", "LISTEN"}:
            continue
        try:
            address, port = split_host_port(parts[4])
        except ValueError:
            continue
        rows.append(_row(protocol, address, port))
    return rows


def _decode_ipv4(hexip: str) -> str:
    raw = bytes.fromhex(hexip)
    return str(ipaddress.IPv4Address(int.from_bytes(raw, "little")))


def _decode_ipv6(hexip: str) -> str:
    raw = bytes.fromhex(hexip)
    groups = [raw[index : index + 4][::-1] for index in range(0, 16, 4)]
    return str(ipaddress.IPv6Address(b"".join(groups)))


def parse_proc_net(text: str, ipv6: bool) -> list[dict]:
    rows = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        local, _remote, state = parts[1], parts[2], parts[3]
        if state != "0A":
            continue
        hexip, hexport = local.split(":", 1)
        address = _decode_ipv6(hexip) if ipv6 else _decode_ipv4(hexip)
        rows.append(_row("tcp", address, int(hexport, 16)))
    return rows


def read_host_listeners() -> list[dict]:
    rows: list[dict] = []
    try:
        completed = subprocess.run(
            ["ss", "-H", "-lntu"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if completed.returncode == 0 and completed.stdout.strip():
            rows = parse_ss(completed.stdout)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    if not rows:
        tcp = Path("/proc/net/tcp")
        tcp6 = Path("/proc/net/tcp6")
        if tcp.is_file():
            rows.extend(parse_proc_net(tcp.read_text(encoding="utf-8", errors="replace"), ipv6=False))
        if tcp6.is_file():
            rows.extend(parse_proc_net(tcp6.read_text(encoding="utf-8", errors="replace"), ipv6=True))
    # Stable order for the panel: public-facing listeners first, then port number.
    return sorted(rows, key=lambda row: (0 if row["possibly_public"] else 1, row["port"], row["address"], row["protocol"]))


def inventory_warning(*, host_network: bool, nft_backend: str) -> str:
    if host_network:
        if nft_backend == "disabled":
            return (
                "Host network is enabled, so this list is the host. "
                "nft backend is still disabled: Preview/Apply will not change host nftables until backend is local or agent."
            )
        return (
            "Host network is enabled. This list is the host listeners. "
            "After Preview/Apply in enforce mode, table inet port_warden sits in front of inbound traffic; "
            "ports not allowed, excluded, or management-SSH stay dropped."
        )
    return (
        "This process is not in the host network namespace, so the list is only what the container can see "
        "(not host SSH or other host services). Use the default docker compose host-network deploy, "
        "or a host install, for a real host port inventory and firewall."
    )


def check_reachability(host: str, port: int, allowed: list[str], timeout: float = 2.0) -> dict:
    """TCP-connect one explicitly configured operator-owned address. Never scans a range."""
    try:
        ipaddress.ip_address(host)
    except ValueError as exc:
        raise PermissionError("Reachability targets must be literal IP addresses, not hostnames.") from exc
    needle = f"{host}:{port}"
    if needle not in set(allowed):
        raise PermissionError(
            "Refusing reachability check: the host:port is not in the configured operator-owned target list."
        )
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    error = ""
    open_ok = False
    try:
        sock.connect((host, port))
        open_ok = True
    except OSError as exc:
        error = exc.strerror or str(exc)
    finally:
        sock.close()
    return {
        "host": host,
        "port": port,
        "tcp_connect": open_ok,
        "error": error,
        "note": REACHABILITY_NOTE,
    }

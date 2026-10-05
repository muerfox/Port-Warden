from __future__ import annotations

import ipaddress
import os
import re
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

_USERS = re.compile(r'users:\(\("(?P<name>[^"]+)",pid=(?P<pid>\d+)', re.IGNORECASE)

# process name pattern → human service label
_SERVICE_HINTS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^(sshd|ssh)$", re.I), "SSH"),
    (re.compile(r"sshd", re.I), "SSH"),
    (re.compile(r"^(nginx|apache2?|httpd|caddy|traefik|haproxy)$", re.I), "HTTP"),
    (re.compile(r"docker-proxy", re.I), "Docker publish"),
    (re.compile(r"containerd|dockerd", re.I), "Docker"),
    (re.compile(r"^(postgres|postmaster)$", re.I), "PostgreSQL"),
    (re.compile(r"^mysqld?", re.I), "MySQL/MariaDB"),
    (re.compile(r"^redis-server$", re.I), "Redis"),
    (re.compile(r"^mongod$", re.I), "MongoDB"),
    (re.compile(r"^(named|systemd-resolve|dnsmasq)$", re.I), "DNS"),
    (re.compile(r"^(ntpd|chronyd)$", re.I), "NTP"),
    (re.compile(r"^(smtp|master|postfix|exim)", re.I), "Mail"),
    (re.compile(r"^python", re.I), "Python"),
    (re.compile(r"^node$", re.I), "Node.js"),
    (re.compile(r"^java$", re.I), "Java"),
    (re.compile(r"^systemd$", re.I), "systemd"),
]


def classify_address(address: str) -> str:
    if address in {"0.0.0.0", "::", "*"}:
        return "all_interfaces"
    ip = ipaddress.ip_address(address)
    if ip.is_loopback:
        return "local"
    if ip.is_private or ip.is_link_local:
        return "private_interface"
    return "public_address"


def service_label(process: str, port: int | None = None) -> str:
    name = (process or "").strip()
    if not name:
        return "unknown"
    base = Path(name).name
    for pattern, label in _SERVICE_HINTS:
        if pattern.search(base) or pattern.search(name):
            return label
    if port == 22:
        return "likely SSH"
    return base


def is_ssh_process(process: str) -> bool:
    return service_label(process) == "SSH"


def _row(
    protocol: str,
    address: str,
    port: int,
    *,
    process: str = "",
    pid: int | None = None,
    inode: int | None = None,
) -> dict:
    kind = classify_address(address)
    proc = process or ""
    return {
        "protocol": protocol,
        "address": address,
        "port": port,
        "scope": kind,
        "scope_label": CLASS_LABELS[kind],
        "possibly_public": kind in {"all_interfaces", "public_address"},
        "process": proc,
        "pid": pid,
        "inode": inode,
        "service": service_label(proc, port),
        "is_ssh": is_ssh_process(proc),
    }


def split_host_port(value: str) -> tuple[str, int]:
    if value.startswith("["):
        host, _, port = value[1:].rpartition("]:")
        return host, int(port)
    host, _, port = value.rpartition(":")
    return host, int(port)


def _process_from_users(text: str) -> tuple[str, int | None]:
    match = _USERS.search(text)
    if not match:
        return "", None
    return match.group("name"), int(match.group("pid"))


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
        process, pid = _process_from_users(line)
        rows.append(_row(protocol, address, port, process=process, pid=pid))
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
        if len(parts) < 10:
            continue
        local, _remote, state = parts[1], parts[2], parts[3]
        if state != "0A":
            continue
        hexip, hexport = local.split(":", 1)
        address = _decode_ipv6(hexip) if ipv6 else _decode_ipv4(hexip)
        try:
            inode = int(parts[9])
        except ValueError:
            inode = None
        rows.append(_row("tcp", address, int(hexport, 16), inode=inode))
    return rows


def _cmdline(pid: int) -> str:
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return ""
    text = raw.replace(b"\x00", b" ").decode("utf-8", "replace").strip()
    if not text:
        try:
            text = Path(f"/proc/{pid}/comm").read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            return ""
    return text.split()[0] if text else ""


def inode_process_map() -> dict[int, tuple[str, int]]:
    """Map socket inode → (process, pid) by walking /proc/*/fd when readable."""
    found: dict[int, tuple[str, int]] = {}
    proc = Path("/proc")
    try:
        entries = list(proc.iterdir())
    except OSError:
        return found
    for entry in entries:
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        fd_dir = entry / "fd"
        try:
            fds = list(fd_dir.iterdir())
        except OSError:
            continue
        for fd in fds:
            try:
                target = os.readlink(fd)
            except OSError:
                continue
            if not target.startswith("socket:["):
                continue
            try:
                inode = int(target[8:-1])
            except ValueError:
                continue
            if inode in found:
                continue
            name = _cmdline(pid) or f"pid:{pid}"
            found[inode] = (Path(name).name, pid)
    return found


def host_pid_namespace() -> bool:
    """True when /proc/1 looks like host init (systemd/init), not the container entrypoint."""
    try:
        raw = Path("/proc/1/cmdline").read_bytes().replace(b"\x00", b" ").decode("utf-8", "replace").strip()
    except OSError:
        return False
    if not raw:
        return False
    first = Path(raw.split()[0]).name.lower()
    lowered = raw.lower()
    return first in {"systemd", "init"} or lowered.startswith("/sbin/init") or "systemd" in lowered[:80]


def enrich_with_inodes(rows: list[dict]) -> list[dict]:
    if not rows or all(row.get("process") for row in rows):
        return rows
    mapping = inode_process_map()
    if not mapping:
        return rows
    enriched = []
    for row in rows:
        if row.get("process"):
            enriched.append(row)
            continue
        inode = row.get("inode")
        if inode and inode in mapping:
            process, pid = mapping[inode]
            enriched.append(
                _row(
                    row["protocol"],
                    row["address"],
                    row["port"],
                    process=process,
                    pid=pid,
                    inode=inode,
                )
            )
        else:
            enriched.append(row)
    return enriched


def read_host_listeners() -> list[dict]:
    rows: list[dict] = []
    # -p includes the owning process when capabilities allow it.
    for args in (["ss", "-H", "-lntup"], ["ss", "-H", "-lntu"]):
        try:
            completed = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        if completed.returncode == 0 and completed.stdout.strip():
            rows = parse_ss(completed.stdout)
            if rows:
                break
    if not rows:
        tcp = Path("/proc/net/tcp")
        tcp6 = Path("/proc/net/tcp6")
        if tcp.is_file():
            rows.extend(parse_proc_net(tcp.read_text(encoding="utf-8", errors="replace"), ipv6=False))
        if tcp6.is_file():
            rows.extend(parse_proc_net(tcp6.read_text(encoding="utf-8", errors="replace"), ipv6=True))
    # Walking /proc only yields host process names when we share the host PID namespace.
    # Otherwise inode matches stay inside the container (often python as pid 1).
    if host_pid_namespace():
        rows = enrich_with_inodes(rows)
    return sorted(
        rows,
        key=lambda row: (0 if row["possibly_public"] else 1, row["port"], row["address"], row["protocol"]),
    )


def detect_ssh_ports(rows: list[dict] | None = None) -> list[int]:
    rows = rows if rows is not None else read_host_listeners()
    ports = sorted({int(row["port"]) for row in rows if row.get("is_ssh") and row.get("protocol") == "tcp"})
    return ports


def inventory_warning(*, host_network: bool, nft_backend: str, host_pid: bool = False) -> str:
    if host_network:
        sees_host_procs = host_pid or host_pid_namespace()
        if not sees_host_procs:
            return (
                "Host network is enabled, so listening ports are from the host, "
                "but this process is still in a container PID namespace. "
                "Process names (for example python pid 1) are container-local. "
                "Recreate with Compose pid: host (PORT_WARDEN_HOST_PID=1) to label host services."
            )
        if nft_backend == "disabled":
            return (
                "Host network and host PID are enabled, so this list is the host. "
                "nft backend is still disabled: Preview/Apply will not change host nftables until backend is local or agent."
            )
        return (
            "Host network and host PID are enabled. Process names come from host listeners. "
            "SSH is detected automatically from sshd. After Preview/Apply in enforce mode, "
            "ports that are not kept open or management-SSH stay dropped."
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

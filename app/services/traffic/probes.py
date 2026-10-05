from __future__ import annotations

import json
import threading
import time
from collections import deque
from pathlib import Path

from sqlalchemy.orm import Session, sessionmaker

from app.config import Settings
from app.logging_json import JsonLogger
from app.services.events import record_event
from app.services.firewall.backend import NftError
from app.services.traffic.nft_log import parse_nft_drop
from app.timeutil import utcnow

PROBE_SETS = ("probe_tcp", "probe_udp")


def _port_from_elem(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 1 <= value <= 65535 else None
    if isinstance(value, str) and value.isdigit():
        port = int(value)
        return port if 1 <= port <= 65535 else None
    if isinstance(value, dict):
        if "val" in value:
            return _port_from_elem(value.get("val"))
        if "elem" in value:
            return _port_from_elem(value.get("elem"))
    return None


def _packets_from_elem(value: object) -> int:
    if not isinstance(value, dict):
        return 0
    counter = value.get("counter")
    if isinstance(counter, dict):
        try:
            return max(0, int(counter.get("packets") or 0))
        except (TypeError, ValueError):
            return 0
    if "elem" in value and isinstance(value["elem"], dict):
        return _packets_from_elem(value["elem"])
    return 0


def parse_probe_set_json(payload: dict | list, *, protocol: str) -> list[dict]:
    """Normalize `nft -j list set` output into port/packet rows."""
    rows: list[dict] = []
    root = payload.get("nftables") if isinstance(payload, dict) else payload
    if not isinstance(root, list):
        return rows
    for item in root:
        if not isinstance(item, dict):
            continue
        set_obj = item.get("set")
        if not isinstance(set_obj, dict):
            continue
        elements = set_obj.get("elem") or set_obj.get("elements") or []
        if not isinstance(elements, list):
            continue
        for element in elements:
            port = _port_from_elem(element)
            if port is None and isinstance(element, dict):
                port = _port_from_elem(element.get("val") or element.get("elem"))
            if port is None:
                continue
            packets = _packets_from_elem(element) if isinstance(element, dict) else 0
            if packets <= 0:
                packets = 1
            rows.append({"port": port, "protocol": protocol, "packets": packets})
    return rows


def read_probe_counters(backend) -> list[dict]:
    """Read live probe_* set counters from the local nft backend."""
    reader = getattr(backend, "list_set_json", None)
    if not callable(reader):
        return []
    found: list[dict] = []
    for set_name in PROBE_SETS:
        protocol = "tcp" if set_name.endswith("tcp") else "udp"
        try:
            payload = reader(set_name)
        except NftError:
            continue
        except Exception:
            continue
        if not payload:
            continue
        found.extend(parse_probe_set_json(payload, protocol=protocol))
    # Merge duplicate ports (unlikely across tcp/udp for chart keying by port).
    merged: dict[tuple[str, int], dict] = {}
    for row in found:
        key = (row["protocol"], int(row["port"]))
        item = merged.setdefault(
            key,
            {"port": int(row["port"]), "protocol": row["protocol"], "packets": 0},
        )
        item["packets"] += int(row["packets"])
    return sorted(merged.values(), key=lambda row: (-row["packets"], row["port"], row["protocol"]))


def snapshot_path(settings: Settings) -> Path:
    return Path(settings.data_dir) / "probe_snapshot.json"


def load_snapshot(settings: Settings) -> dict[str, int]:
    path = snapshot_path(settings)
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    out: dict[str, int] = {}
    for key, value in data.items():
        try:
            out[str(key)] = max(0, int(value))
        except (TypeError, ValueError):
            continue
    return out


def save_snapshot(settings: Settings, values: dict[str, int]) -> None:
    path = snapshot_path(settings)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(values, separators=(",", ":")), encoding="utf-8")


def sync_probe_deltas(
    db: Session,
    settings: Settings,
    backend,
    logger: JsonLogger,
) -> list[dict]:
    """Turn counter growth into port_probe events for Traffic history."""
    current_rows = read_probe_counters(backend)
    current = {f"{row['protocol']}/{row['port']}": int(row["packets"]) for row in current_rows}
    previous = load_snapshot(settings)
    emitted: list[dict] = []
    for key, packets in current.items():
        prior = int(previous.get(key, 0))
        # Counter reset (table reapplied) — treat full value as new pressure.
        delta = packets if packets < prior else packets - prior
        if delta <= 0:
            continue
        protocol, _, port_text = key.partition("/")
        port = int(port_text)
        record_event(
            db,
            logger,
            "port_probe",
            src_ip="",
            dst_port=port,
            action="nft_drop",
            details={"protocol": protocol, "packets": delta, "source": "probe_set"},
        )
        emitted.append({"protocol": protocol, "port": port, "packets": delta})
    save_snapshot(settings, current)
    return emitted


def record_drop_line(
    db: Session,
    logger: JsonLogger,
    line: str,
    *,
    recent: deque[str] | None = None,
) -> dict | None:
    parsed = parse_nft_drop(line)
    if parsed is None:
        return None
    stamp = utcnow().strftime("%Y-%m-%dT%H:%M")
    fingerprint = f"{stamp}|{parsed['src_ip']}|{parsed['protocol']}|{parsed['dst_port']}"
    if recent is not None:
        if fingerprint in recent:
            return None
        recent.append(fingerprint)
    record_event(
        db,
        logger,
        "port_probe",
        src_ip=parsed["src_ip"],
        dst_port=parsed["dst_port"],
        action="nft_drop",
        details={"protocol": parsed["protocol"], "source": "kernel_log"},
    )
    return parsed


class ProbePoller:
    """Periodically sync nft probe counters and optionally follow a drop log."""

    def __init__(
        self,
        session_factory: sessionmaker,
        settings: Settings,
        backend,
        logger: JsonLogger,
        *,
        poll_seconds: float = 30.0,
    ) -> None:
        self.session_factory = session_factory
        self.settings = settings
        self.backend = backend
        self.logger = logger
        self.poll_seconds = max(5.0, float(poll_seconds))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._recent: deque[str] = deque(maxlen=5000)
        self._log_offset = 0
        self._log_inode: int | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="port-warden-probes", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def _run(self) -> None:
        while not self._stop.is_set():
            session = self.session_factory()
            try:
                sync_probe_deltas(session, self.settings, self.backend, self.logger)
                self._drain_log(session)
                session.commit()
            except Exception:
                session.rollback()
                self.logger.emit(
                    "probe_sync_error",
                    action="skip",
                    src_ip="",
                    dst_port="",
                    rule_id="",
                )
            finally:
                session.close()
            self._stop.wait(self.poll_seconds)

    def _log_paths(self) -> list[Path]:
        configured = (self.settings.nft_log_path or "").strip()
        candidates = []
        if configured:
            candidates.append(Path(configured))
        candidates.extend(
            [
                Path("/var/log/host/kern.log"),
                Path("/var/log/host/messages"),
                Path("/var/log/host/syslog"),
                Path("/var/log/kern.log"),
                Path("/var/log/messages"),
                Path("/var/log/syslog"),
            ]
        )
        seen: set[str] = set()
        out: list[Path] = []
        for path in candidates:
            key = str(path)
            if key in seen:
                continue
            seen.add(key)
            if path.is_file():
                out.append(path)
        return out

    def _drain_log(self, session: Session) -> None:
        paths = self._log_paths()
        if not paths:
            return
        path = paths[0]
        try:
            stat = path.stat()
        except OSError:
            return
        if self._log_inode != stat.st_ino:
            self._log_inode = stat.st_ino
            # On first open / rotation, read only the tail to avoid historic flood.
            self._log_offset = max(0, stat.st_size - 256_000)
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                handle.seek(self._log_offset)
                for line in handle:
                    record_drop_line(session, self.logger, line, recent=self._recent)
                self._log_offset = handle.tell()
        except OSError:
            return

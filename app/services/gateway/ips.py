from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import time
from collections import deque
from pathlib import Path

from sqlalchemy.orm import Session, sessionmaker

from app.config import Settings
from app.logging_json import JsonLogger
from app.services.events import record_event


def suricata_dir(settings: Settings) -> Path:
    return Path(settings.data_dir) / "suricata"


def pid_path(settings: Settings) -> Path:
    return suricata_dir(settings) / "suricata.pid"


def eve_path(settings: Settings) -> Path:
    return suricata_dir(settings) / "eve.json"


def binary_available(binary: str) -> bool:
    if not binary:
        return False
    path = Path(binary)
    if path.is_file() and os.access(path, os.X_OK):
        return True
    return shutil.which(binary) is not None


def assert_ips_ready(settings: Settings) -> None:
    if not binary_available(settings.suricata_bin):
        raise ValueError("IPS is enabled but suricata is not installed")
    rules = (settings.suricata_rules or "").strip()
    if not rules or not Path(rules).is_file():
        raise ValueError("IPS is enabled but PORT_WARDEN_SURICATA_RULES is not a readable rules file")


def write_config(settings: Settings) -> Path:
    rules = Path(settings.suricata_rules)
    directory = suricata_dir(settings)
    directory.mkdir(parents=True, exist_ok=True)
    config = directory / "suricata.yaml"
    config.write_text(
        "\n".join(
            [
                "%YAML 1.1",
                "---",
                "outputs:",
                "  - eve-log:",
                "      enabled: yes",
                "      filetype: regular",
                "      filename: eve.json",
                "      types:",
                "        - alert",
                "nfq:",
                "  mode: repeat",
                "  repeat-mark: 1",
                "  repeat-mask: 1",
                "default-rule-path: " + json.dumps(str(rules.parent)),
                "rule-files:",
                "  - " + json.dumps(rules.name),
                "",
            ]
        ),
        encoding="utf-8",
    )
    return config


def suricata_running(settings: Settings) -> bool:
    path = pid_path(settings)
    if not path.is_file():
        return False
    try:
        pid = int(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def start_suricata(settings: Settings) -> None:
    assert_ips_ready(settings)
    if suricata_running(settings):
        return
    config = write_config(settings)
    directory = suricata_dir(settings)
    proc = subprocess.Popen(
        [
            settings.suricata_bin,
            "-c",
            str(config),
            "-q",
            "0",
            "--pidfile",
            str(pid_path(settings)),
            "-l",
            str(directory),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    time.sleep(0.4)
    if proc.poll() is not None:
        err = (proc.stderr.read() if proc.stderr else "")[:300]
        raise RuntimeError(f"suricata exited: {err}")


def stop_suricata(settings: Settings) -> None:
    path = pid_path(settings)
    if not path.is_file():
        return
    try:
        pid = int(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return
    try:
        os.kill(pid, 15)
    except OSError:
        return
    path.unlink(missing_ok=True)


def parse_eve_alert(line: str) -> dict | None:
    text = (line or "").strip()
    if not text:
        return None
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    if payload.get("event_type") != "alert":
        return None
    alert = payload.get("alert") or {}
    port = payload.get("dest_port")
    try:
        dst_port = int(port) if port is not None else None
    except (TypeError, ValueError):
        dst_port = None
    return {
        "src_ip": str(payload.get("src_ip") or ""),
        "dst_port": dst_port,
        "signature": str(alert.get("signature") or ""),
        "timestamp": str(payload.get("timestamp") or ""),
    }


class IpsWatcher:
    """Read Suricata eve.json alerts into Port Warden events."""

    def __init__(self, session_factory: sessionmaker, settings: Settings, logger: JsonLogger) -> None:
        self.session_factory = session_factory
        self.settings = settings
        self.logger = logger
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._offset = 0
        self._inode: int | None = None
        self._recent: deque[str] = deque(maxlen=4000)

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="port-warden-ips", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def _run(self) -> None:
        while not self._stop.is_set():
            session = self.session_factory()
            try:
                self._drain(session)
                session.commit()
            except Exception:
                session.rollback()
            finally:
                session.close()
            self._stop.wait(5)

    def _drain(self, session: Session) -> None:
        path = eve_path(self.settings)
        if not path.is_file():
            return
        try:
            stat = path.stat()
        except OSError:
            return
        if self._inode != stat.st_ino:
            self._inode = stat.st_ino
            self._offset = max(0, stat.st_size - 256_000)
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                handle.seek(self._offset)
                for line in handle:
                    self._record(session, line)
                self._offset = handle.tell()
        except OSError:
            return

    def _record(self, session: Session, line: str) -> None:
        parsed = parse_eve_alert(line)
        if parsed is None:
            return
        fingerprint = f"{parsed['timestamp']}|{parsed['src_ip']}|{parsed['dst_port']}|{parsed['signature']}"
        if fingerprint in self._recent:
            return
        self._recent.append(fingerprint)
        record_event(
            session,
            self.logger,
            "ips_alert",
            src_ip=parsed["src_ip"],
            dst_port=parsed["dst_port"],
            action="alert",
            details={"signature": parsed["signature"][:200]},
        )

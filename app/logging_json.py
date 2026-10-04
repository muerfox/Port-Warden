from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from app.timeutil import iso, utcnow

REDACT_KEYS = {
    "password",
    "secret",
    "secret_key",
    "token",
    "confirm_token",
    "csrf_token",
    "authorization",
    "totp",
    "totp_secret",
    "script",
    "password_hash",
}


class JsonLogger:
    def __init__(self, directory: Path, max_bytes: int, retention_days: int) -> None:
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = directory / "port-warden.jsonl"
        self.max_bytes = max_bytes
        self.retention_days = retention_days
        self._lock = threading.Lock()

    def emit(self, event_type: str, **fields: object) -> dict:
        clean = {}
        for key, value in fields.items():
            if key.lower() in REDACT_KEYS:
                continue
            clean[key] = value
        record = {
            "timestamp": iso(utcnow()),
            "event_type": event_type,
            **clean,
        }
        line = json.dumps(record, default=str, separators=(",", ":"), sort_keys=True)
        with self._lock:
            self._rotate_if_needed()
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        return record

    def _rotate_if_needed(self) -> None:
        if not self.path.exists() or self.path.stat().st_size < self.max_bytes:
            return
        rotated = self.directory / "port-warden.jsonl.1"
        if rotated.exists():
            rotated.unlink()
        self.path.replace(rotated)

    def purge(self) -> int:
        cutoff = time.time() - self.retention_days * 86400
        removed = 0
        for path in self.directory.glob("port-warden.jsonl.*"):
            if path.stat().st_mtime < cutoff:
                path.unlink()
                removed += 1
        return removed

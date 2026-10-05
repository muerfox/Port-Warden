from __future__ import annotations

import json
from pathlib import Path

from app.config import Settings

_KEYS = ("net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding")


def _proc_path(key: str) -> Path:
    return Path("/proc/sys") / Path(*key.split("."))


def read_sysctl(key: str) -> str:
    try:
        return _proc_path(key).read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def write_sysctl(key: str, value: str) -> None:
    path = _proc_path(key)
    path.write_text(str(value).strip() + "\n", encoding="utf-8")


def _prev_path(settings: Settings) -> Path:
    return Path(settings.data_dir) / "sysctl-prev.json"


def enable_forwarding(settings: Settings) -> None:
    path = _prev_path(settings)
    previous: dict[str, str] = {}
    if path.is_file():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                previous = {str(key): str(value) for key, value in loaded.items()}
        except (OSError, json.JSONDecodeError):
            previous = {}
    for key in _KEYS:
        if key not in previous:
            current = read_sysctl(key)
            if current != "":
                previous[key] = current
        write_sysctl(key, "1")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(previous, separators=(",", ":")), encoding="utf-8")


def restore_forwarding(settings: Settings) -> None:
    path = _prev_path(settings)
    if not path.is_file():
        return
    try:
        previous = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    if not isinstance(previous, dict):
        return
    for key in _KEYS:
        value = previous.get(key)
        if value is None:
            continue
        write_sysctl(key, str(value))
    path.unlink(missing_ok=True)

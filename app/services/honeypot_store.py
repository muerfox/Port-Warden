from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Honeypot

DECOYS = (
    ("ssh-decoy", "ssh", 2222, "Low-interaction SSH banner. Monitoring only. No shell."),
    ("http-decoy", "http", 8088, "Low-interaction HTTP response. Monitoring only. No application."),
)


def ensure_honeypots(db: Session) -> None:
    for name, kind, port, note in DECOYS:
        if db.scalar(select(Honeypot).where(Honeypot.name == name)) is None:
            db.add(Honeypot(name=name, kind=kind, listen_port=port, enabled=False, note=note))


def write_desired(db: Session, directory: Path) -> None:
    rows = db.scalars(select(Honeypot).order_by(Honeypot.name)).all()
    payload = [
        {
            "name": row.name,
            "kind": row.kind,
            "listen_port": row.listen_port,
            "enabled": row.enabled,
            "label": "decoy",
        }
        for row in rows
    ]
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "desired.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")


def read_telemetry(directory: Path, limit: int = 200) -> list[dict]:
    events: list[dict] = []
    if not directory.is_dir():
        return events
    for path in sorted(directory.glob("*.jsonl")):
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines[-limit:]:
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                item.setdefault("source_file", path.name)
                events.append(item)
    events.sort(key=lambda item: str(item.get("timestamp", "")), reverse=True)
    return events[:limit]

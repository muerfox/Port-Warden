from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings
from app.models import Event, Honeypot
from app.services.honeypot_store import read_telemetry
from app.services.traffic.probes import read_probe_counters
from app.timeutil import iso, utcnow

ATTACK_TYPES = ("auth_failure", "ban", "login_failure", "honeypot", "port_probe")


def _parse_ts(value: object) -> datetime | None:
    if not value:
        return None
    text = str(value).strip().rstrip("Z")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed.replace(tzinfo=None)


def _kind_port(kind: str, honeypot_ports: dict[str, int]) -> int | None:
    if kind in honeypot_ports:
        return honeypot_ports[kind]
    if kind == "ssh":
        return 2222
    if kind == "http":
        return 8088
    return None


def _event_weight(row: Event) -> int:
    """port_probe rows from probe sets carry a packet delta in details."""
    if row.event_type != "port_probe":
        return 1
    try:
        details = row.details or ""
        if not details:
            return 1
        payload = json.loads(details)
        packets = int(payload.get("packets") or 1)
        return max(1, packets)
    except (TypeError, ValueError, json.JSONDecodeError):
        return 1


def port_attack_stats(
    db: Session,
    settings: Settings,
    *,
    hours: int = 24,
    limit: int = 12,
    backend=None,
) -> dict:
    """Aggregate attack-like events and live nft drop counters by destination port."""
    hours = max(1, min(int(hours), 24 * 30))
    limit = max(1, min(int(limit), 50))
    now = utcnow()
    since = now - timedelta(hours=hours)

    buckets: dict[int, dict] = {}

    def touch(port: int, src: str, event_type: str, when: datetime, weight: int = 1) -> None:
        if not 1 <= port <= 65535:
            return
        item = buckets.setdefault(
            port,
            {
                "port": port,
                "count": 0,
                "sources": set(),
                "types": defaultdict(int),
                "last_seen": None,
                "protocols": set(),
            },
        )
        item["count"] += max(1, int(weight))
        if src:
            item["sources"].add(src)
        item["types"][event_type] += max(1, int(weight))
        if item["last_seen"] is None or when > item["last_seen"]:
            item["last_seen"] = when

    rows = db.scalars(
        select(Event)
        .where(Event.timestamp >= since)
        .where(Event.event_type.in_(ATTACK_TYPES))
        .where(Event.dst_port.is_not(None))
    ).all()
    for row in rows:
        touch(int(row.dst_port), row.src_ip, row.event_type, row.timestamp, _event_weight(row))

    honeypot_ports = {
        row.kind: int(row.listen_port)
        for row in db.scalars(select(Honeypot)).all()
    }
    for item in read_telemetry(Path(settings.data_dir) / "honeypot", limit=2000):
        when = _parse_ts(item.get("timestamp")) or now
        if when < since:
            continue
        detail = str(item.get("detail", ""))
        if detail == "decoy-listening":
            continue
        port = item.get("dst_port") or item.get("port") or _kind_port(str(item.get("kind", "")), honeypot_ports)
        if port is None:
            continue
        touch(int(port), str(item.get("src") or item.get("src_ip") or ""), "honeypot", when)

    live_probes = read_probe_counters(backend) if backend is not None else []
    for probe in live_probes:
        # Live counters already cover the rolling set timeout window; fold them in
        # when event history is sparse so the UI is useful right after Apply.
        port = int(probe["port"])
        packets = int(probe["packets"])
        existing = buckets.get(port)
        if existing is None or existing["count"] < packets:
            need = packets - (existing["count"] if existing else 0)
            touch(port, "", "nft_drop", now, need)
            buckets[port]["protocols"].add(probe["protocol"])

    ranked = sorted(buckets.values(), key=lambda item: (-item["count"], item["port"]))[:limit]
    total = sum(item["count"] for item in ranked)
    max_count = max((item["count"] for item in ranked), default=0)
    chart = []
    for item in ranked:
        count = int(item["count"])
        chart.append(
            {
                "port": item["port"],
                "count": count,
                "unique_sources": len(item["sources"]),
                "types": dict(sorted(item["types"].items())),
                "last_seen": iso(item["last_seen"]) if item["last_seen"] else "",
                "share": round((count / total) * 100, 1) if total else 0.0,
                "bar_pct": round((count / max_count) * 100, 1) if max_count else 0.0,
                "protocols": sorted(item["protocols"]) if item["protocols"] else ["tcp"],
            }
        )

    # Hourly timeline for the top ports (for a second spark-style chart).
    top_ports = {item["port"] for item in chart[:5]}
    hour_counts: dict[str, dict[int, int]] = defaultdict(lambda: defaultdict(int))
    for row in rows:
        if row.dst_port not in top_ports:
            continue
        key = row.timestamp.replace(minute=0, second=0, microsecond=0).strftime("%Y-%m-%dT%H:00")
        hour_counts[key][int(row.dst_port)] += _event_weight(row)
    timeline = []
    cursor = since.replace(minute=0, second=0, microsecond=0)
    end = now.replace(minute=0, second=0, microsecond=0)
    while cursor <= end:
        key = cursor.strftime("%Y-%m-%dT%H:00")
        point = {"hour": key, "ports": {str(port): hour_counts[key].get(port, 0) for port in sorted(top_ports)}}
        point["total"] = sum(point["ports"].values())
        timeline.append(point)
        cursor += timedelta(hours=1)

    visible_timeline = timeline[-48:]
    discovered = [
        {
            "port": item["port"],
            "count": item["count"],
            "unique_sources": item["unique_sources"],
            "types": item["types"],
        }
        for item in chart
    ]
    return {
        "hours": hours,
        "since": iso(since),
        "until": iso(now),
        "total_events": total,
        "ports": chart,
        "discovered": discovered,
        "live_probes": live_probes,
        "timeline": visible_timeline,
        "timeline_peak": max((point["total"] for point in visible_timeline), default=1) or 1,
        "attack_types": list(ATTACK_TYPES) + ["nft_drop"],
    }

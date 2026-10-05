from app.services.analytics.ports import port_attack_stats
from app.services.traffic.nft_log import parse_nft_drop
from app.services.traffic.probes import parse_probe_set_json, record_drop_line, sync_probe_deltas


def test_parse_nft_drop_line():
    line = (
        'kernel: pw:drop IN=eth0 OUT= MAC=ff SRC=203.0.113.10 DST=198.51.100.20 '
        "LEN=60 PROTO=TCP SPT=54321 DPT=23 WINDOW=64240"
    )
    parsed = parse_nft_drop(line)
    assert parsed == {"src_ip": "203.0.113.10", "dst_port": 23, "protocol": "tcp"}
    assert parse_nft_drop("unrelated line") is None


def test_parse_probe_set_json_counts_ports():
    payload = {
        "nftables": [
            {
                "set": {
                    "family": "inet",
                    "name": "probe_tcp",
                    "table": "port_warden",
                    "type": "inet_service",
                    "elem": [
                        {"elem": {"val": 23, "counter": {"packets": 12, "bytes": 720}}},
                        {"elem": {"val": 445, "counter": {"packets": 3, "bytes": 180}}},
                    ],
                }
            }
        ]
    }
    rows = parse_probe_set_json(payload, protocol="tcp")
    assert rows == [
        {"port": 23, "protocol": "tcp", "packets": 12},
        {"port": 445, "protocol": "tcp", "packets": 3},
    ]


class _FakeBackend:
    def __init__(self, payload):
        self.payload = payload

    def list_set_json(self, set_name: str):
        if set_name != "probe_tcp":
            return None
        return self.payload


def test_sync_probe_deltas_emits_port_probe(auth, app, tmp_path):
    app.state.settings.data_dir = tmp_path
    payload = {
        "nftables": [
            {
                "set": {
                    "elem": [
                        {"elem": {"val": 23, "counter": {"packets": 5, "bytes": 300}}},
                    ]
                }
            }
        ]
    }
    backend = _FakeBackend(payload)
    db = app.state.session_factory()
    try:
        emitted = sync_probe_deltas(db, app.state.settings, backend, app.state.json_log)
        db.commit()
        assert emitted == [{"protocol": "tcp", "port": 23, "packets": 5}]
        # Second sync with same counters should not re-emit.
        assert sync_probe_deltas(db, app.state.settings, backend, app.state.json_log) == []
        db.commit()
        stats = port_attack_stats(db, app.state.settings, hours=24, limit=10, backend=backend)
    finally:
        db.close()
    assert stats["ports"][0]["port"] == 23
    assert stats["ports"][0]["count"] >= 5


def test_record_drop_line_feeds_traffic(auth, app):
    db = app.state.session_factory()
    try:
        parsed = record_drop_line(
            db,
            app.state.json_log,
            "pw:drop SRC=198.51.100.9 DST=10.0.0.1 PROTO=TCP SPT=1 DPT=3389",
        )
        db.commit()
        assert parsed["dst_port"] == 3389
        stats = port_attack_stats(db, app.state.settings, hours=24, limit=10)
    finally:
        db.close()
    assert stats["ports"][0]["port"] == 3389
    assert stats["ports"][0]["unique_sources"] == 1


def test_live_probe_counters_fill_empty_history(auth, app):
    payload = {
        "nftables": [
            {
                "set": {
                    "elem": [
                        {"elem": {"val": 21, "counter": {"packets": 9, "bytes": 540}}},
                    ]
                }
            }
        ]
    }
    db = app.state.session_factory()
    try:
        stats = port_attack_stats(
            db,
            app.state.settings,
            hours=24,
            limit=10,
            backend=_FakeBackend(payload),
        )
    finally:
        db.close()
    assert stats["total_events"] >= 9
    assert stats["ports"][0]["port"] == 21
    assert "nft_drop" in stats["ports"][0]["types"]

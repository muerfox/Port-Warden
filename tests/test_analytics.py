from app.services.analytics.ports import port_attack_stats
from app.services.bruteforce.parser import parse_auth_line
from app.services.events import record_event


def test_parser_captures_destination_port():
    parsed = parse_auth_line("Failed password for root from 203.0.113.10 port 2222 ssh2")
    assert parsed == {"src_ip": "203.0.113.10", "reason": "failed_password", "dst_port": 2222}


def test_port_attack_stats_ranks_hottest_port(auth, app):
    db = app.state.session_factory()
    try:
        for _ in range(5):
            record_event(
                db,
                app.state.json_log,
                "auth_failure",
                src_ip="203.0.113.10",
                dst_port=2222,
                action="failed_password",
            )
        for _ in range(2):
            record_event(
                db,
                app.state.json_log,
                "auth_failure",
                src_ip="198.51.100.20",
                dst_port=22,
                action="failed_password",
            )
        record_event(
            db,
            app.state.json_log,
            "login_failure",
            src_ip="203.0.113.55",
            dst_port=9090,
            action="denied",
        )
        db.commit()
        stats = port_attack_stats(db, app.state.settings, hours=24, limit=10)
    finally:
        db.close()

    assert stats["total_events"] == 8
    assert stats["ports"][0]["port"] == 2222
    assert stats["ports"][0]["count"] == 5
    assert stats["ports"][0]["unique_sources"] == 1
    ports = {row["port"]: row["count"] for row in stats["ports"]}
    assert ports[22] == 2
    assert ports[9090] == 1

    api = auth.get("/api/v1/analytics/ports?hours=24")
    assert api.status_code == 200
    assert api.json()["ports"][0]["port"] == 2222

    page = auth.get("/traffic?hours=24")
    assert page.status_code == 200
    assert b"tcp/2222" in page.content
    assert b"Hottest port" in page.content

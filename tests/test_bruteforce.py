from datetime import timedelta

from app.services.bruteforce.observe import observe_ip
from app.services.bruteforce.parser import parse_auth_line
from app.services.records import save_bf_config_fields
from app.timeutil import utcnow


def test_parser_ignores_malformed_lines():
    parsed = parse_auth_line("Failed password for root from 203.0.113.10 port 22 ssh2")
    assert parsed == {"src_ip": "203.0.113.10", "reason": "failed_password", "dst_port": 22}
    assert parse_auth_line("Failed password for invalid user admin from 203.0.113.11 port 22 ssh2")["src_ip"] == "203.0.113.11"
    assert parse_auth_line("Invalid user x from 2001:db8::5")["reason"] == "invalid_user"
    assert parse_auth_line("not a log line") is None
    assert parse_auth_line("Failed password for root from hostname port 22 ssh2") is None
    assert parse_auth_line("x" * 3000) is None
    assert parse_auth_line("Failed password for root from 203.0.113.10; rm -rf /")["src_ip"] == "203.0.113.10"


def test_threshold_bans_and_allowlist_is_spared(auth):
    lists = auth.get("/api/v1/lists").json()["lists"]
    allow = next(item for item in lists if item["name"] == "allowlist")
    added = auth.post(f"/api/v1/lists/{allow['id']}/entries", json={"cidr": "198.51.100.10/32"})
    assert added.status_code == 200
    saved = auth.put(
        "/api/v1/bruteforce/settings",
        json={
            "threshold": 3,
            "window_seconds": 600,
            "ban_seconds": 120,
            "cooldown_seconds": 60,
            "permanent_after": 0,
        },
    )
    assert saved.status_code == 200

    line = "Failed password for root from {ip} port 22 ssh2"
    spared = auth.post(
        "/api/v1/bruteforce/ingest",
        json={"lines": [line.format(ip="198.51.100.10") for _ in range(5)]},
    )
    assert all(item["action"] == "ignored_allowlist" for item in spared.json()["results"])

    banned = auth.post(
        "/api/v1/bruteforce/ingest",
        json={"lines": [line.format(ip="203.0.113.44") for _ in range(3)]},
    )
    actions = [item["action"] for item in banned.json()["results"]]
    assert actions == ["count", "count", "ban"]
    bans = auth.get("/api/v1/bans").json()["bans"]
    assert any(item["ip"] == "203.0.113.44/32" and item["lifted_at"] is None for item in bans)

    cooled = auth.post(
        "/api/v1/bruteforce/ingest",
        json={"lines": [line.format(ip="203.0.113.44")]},
    )
    assert cooled.json()["results"][0]["action"] == "cooldown"


def test_window_and_permanent(tmp_path, settings):
    from app.factory import create_app
    from fastapi.testclient import TestClient
    from tests.conftest import PASSWORD

    settings.bf_permanent_after = 2
    app = create_app(settings)
    with TestClient(app, client=("127.0.0.1", 50), follow_redirects=False) as client:
        login = client.post("/api/v1/auth/login", json={"username": "admin", "password": PASSWORD})
        client.headers["X-CSRF-Token"] = login.json()["csrf_token"]
        db = app.state.session_factory()
        try:
            save_bf_config_fields(
                db,
                {
                    "threshold": 2,
                    "window_seconds": 10,
                    "ban_seconds": 60,
                    "cooldown_seconds": 0,
                    "permanent_after": 2,
                },
            )
            db.commit()
        finally:
            db.close()
        now = utcnow()
        db = app.state.session_factory()
        try:
            first = observe_ip(
                db, app.state.tracker, app.state.settings, app.state.engine, app.state.json_log,
                "203.0.113.70", "failed_password", now=now,
            )
            second = observe_ip(
                db, app.state.tracker, app.state.settings, app.state.engine, app.state.json_log,
                "203.0.113.70", "failed_password", now=now + timedelta(seconds=1),
            )
            assert first["action"] == "count"
            assert second["action"] == "ban"
            assert second["permanent"] is False
            db.commit()
        finally:
            db.close()


def test_tailer_survives_a_bad_callback(tmp_path):
    import time
    from app.services.bruteforce.tail import LogTailer

    path = tmp_path / "auth.log"
    path.write_text("", encoding="utf-8")
    seen = []

    def on_line(line: str) -> None:
        if "explode" in line:
            raise RuntimeError("bad line")
        seen.append(line)

    tail = LogTailer(path, on_line, poll=0.05)
    tail.start()
    time.sleep(0.1)
    with path.open("a", encoding="utf-8") as handle:
        handle.write("explode\nFailed password for root from 203.0.113.5 port 22 ssh2\n")
    time.sleep(0.3)
    tail.stop()
    assert any("203.0.113.5" in line for line in seen)

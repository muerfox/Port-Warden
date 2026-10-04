import json

from app.logging_json import JsonLogger
from app.services.events import record_event


def test_json_log_shape_and_redaction(tmp_path):
    logger = JsonLogger(tmp_path, max_bytes=10_000, retention_days=7)
    record = logger.emit(
        "ban",
        src_ip="203.0.113.10",
        dst_port=22,
        action="ban",
        rule_id="15",
        password="secret-value",
        token="session-token",
    )
    assert record["event_type"] == "ban"
    assert record["src_ip"] == "203.0.113.10"
    assert record["dst_port"] == 22
    assert "password" not in record
    line = (tmp_path / "port-warden.jsonl").read_text(encoding="utf-8")
    payload = json.loads(line)
    assert payload["timestamp"].endswith("Z")
    assert "secret-value" not in line
    assert "session-token" not in line
    assert payload["rule_id"] == "15"


def test_event_row_and_rotation(auth, tmp_path):
    from app.logging_json import JsonLogger

    small = JsonLogger(tmp_path / "rot", max_bytes=40, retention_days=30)
    small.emit("auth_failure", src_ip="203.0.113.1", dst_port="", action="failed_password", rule_id="")
    small.emit("auth_failure", src_ip="203.0.113.2", dst_port="", action="failed_password", rule_id="")
    assert (tmp_path / "rot" / "port-warden.jsonl").exists()
    assert (tmp_path / "rot" / "port-warden.jsonl.1").exists()

    response = auth.get("/api/v1/events")
    assert response.status_code == 200
    exported = auth.get("/api/v1/events/export")
    assert exported.status_code == 200
    assert exported.headers["content-type"].startswith("application/x-ndjson")
    if exported.text.strip():
        first = json.loads(exported.text.splitlines()[0])
        assert "event_type" in first
        assert "timestamp" in first


def test_record_event_fields(app):
    db = app.state.session_factory()
    try:
        record_event(
            db,
            app.state.json_log,
            "auth_failure",
            src_ip="203.0.113.8",
            dst_port=22,
            action="failed_password",
            rule_id="",
            details={"password": "nope", "reason": "failed_password"},
        )
        db.commit()
    finally:
        db.close()
    text = (app.state.settings.data_dir / "logs" / "port-warden.jsonl").read_text(encoding="utf-8")
    assert "203.0.113.8" in text
    assert "nope" not in text
    assert '"event_type":"auth_failure"' in text or '"event_type": "auth_failure"' in text

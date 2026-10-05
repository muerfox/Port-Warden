from sqlalchemy import select

from app.models import Rule
from app.services.firewall.protections import (
    disable_protection,
    enable_protection,
    list_protection_status,
)


def test_enable_recommended_installs_deny_rules(auth):
    listed = auth.get("/api/v1/protections")
    assert listed.status_code == 200
    packs = listed.json()["packs"]
    assert any(item["id"] == "databases" for item in packs)
    assert any(item["id"] == "legacy-remote" for item in packs)

    enabled = auth.post("/api/v1/protections/enable-recommended")
    assert enabled.status_code == 200
    body = enabled.json()
    assert any(item["enabled"] for item in body["packs"] if item["recommended"])

    rules = auth.get("/api/v1/rules").json()["rules"]
    names = {row["name"] for row in rules}
    assert "protect-databases" in names
    assert "protect-legacy-remote" in names
    assert "protect-mail" in names
    db_rule = next(row for row in rules if row["name"] == "protect-databases")
    assert db_rule["action"] == "deny"
    assert "3306" in db_rule["ports"]
    assert "5432" in db_rule["ports"]
    legacy = next(row for row in rules if row["name"] == "protect-legacy-remote")
    assert "23" in legacy["ports"]
    assert "21" in legacy["ports"]

    page = auth.get("/protections")
    assert page.status_code == 200
    assert b"Database and cache ports" in page.content

    disabled = auth.post("/api/v1/protections/databases/disable")
    assert disabled.status_code == 200
    assert disabled.json()["enabled"] is False
    names_after = {row["name"] for row in auth.get("/api/v1/rules").json()["rules"]}
    assert "protect-databases" not in names_after


def test_ssh_22_pack_is_optional_and_idempotent(app):
    db = app.state.session_factory()
    try:
        status = {item["id"]: item for item in list_protection_status(db)}
        assert status["ssh-default-22"]["recommended"] is False
        first = enable_protection(db, "ssh-default-22")
        db.commit()
        assert first["enabled"] is True
        assert "protect-ssh-22" in first["created"]
        second = enable_protection(db, "ssh-default-22")
        db.commit()
        assert "protect-ssh-22" in second["skipped"]
        disable_protection(db, "ssh-default-22")
        db.commit()
        remaining = db.scalars(select(Rule).where(Rule.name == "protect-ssh-22")).first()
        assert remaining is None
    finally:
        db.close()

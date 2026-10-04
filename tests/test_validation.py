from datetime import timedelta

from app.services.firewall.render import Policy, RuleView, render_policy
from app.services.firewall.safeguard import evaluate_lockout
from app.services.firewall.script_guard import assert_safe_script
from app.timeutil import utcnow


def _policy(**kwargs) -> Policy:
    base = dict(
        mode="enforce",
        management_cidrs=["127.0.0.1/32"],
        ssh_port=22,
        allow_cidrs=[],
        deny_cidrs=[],
        ban_cidrs=[],
        rules=[],
    )
    base.update(kwargs)
    return Policy(**base)


def test_rule_validation(auth):
    bad_cidr = auth.post(
        "/api/v1/rules",
        json={"name": "bad", "action": "allow", "direction": "in", "protocol": "tcp", "src_cidr": "999.1.1.1", "ports": "22"},
    )
    assert bad_cidr.status_code == 400

    wide = auth.post(
        "/api/v1/rules",
        json={"name": "wide", "action": "allow", "direction": "in", "protocol": "any"},
    )
    assert wide.status_code == 400

    bad_name = auth.post(
        "/api/v1/rules",
        json={"name": "has space", "action": "deny", "direction": "in", "protocol": "tcp", "ports": "22"},
    )
    assert bad_name.status_code == 400

    created = auth.post(
        "/api/v1/rules",
        json={
            "name": "office-ssh",
            "action": "allow",
            "direction": "in",
            "protocol": "tcp",
            "src_cidr": "198.51.100.0/24",
            "ports": "22",
            "comment": "office",
            "priority": 20,
        },
    )
    assert created.status_code == 200
    assert created.json()["priority"] == 20


def test_denylist_cannot_cover_management(auth):
    lists = auth.get("/api/v1/lists").json()["lists"]
    deny = next(item for item in lists if item["name"] == "denylist")
    blocked = auth.post(f"/api/v1/lists/{deny['id']}/entries", json={"cidr": "127.0.0.0/8"})
    assert blocked.status_code == 400
    allowed = auth.post(f"/api/v1/lists/{deny['id']}/entries", json={"cidr": "203.0.113.0/24"})
    assert allowed.status_code == 200


def test_render_orders_rules_and_skips_expired():
    now = utcnow()
    rules = [
        RuleView("later", "allow", "in", "tcp", None, None, "443", "", 50),
        RuleView("sooner", "deny", "in", "tcp", "203.0.113.9/32", None, "25", "", 10),
        RuleView("old", "deny", "in", "tcp", "203.0.113.8/32", None, "25", "", 1, True, now - timedelta(seconds=30)),
    ]
    rendered = render_policy(_policy(rules=rules), now)
    script = rendered.script
    assert "policy drop;" in script
    assert 'tcp dport 22 accept comment "pw:management-ssh"' in script
    assert 'tcp dport { 80, 443, 8080 } accept comment "pw:excluded-ports"' not in script
    kept = render_policy(_policy(rules=rules, excluded_ports=[80, 443, 8080]), now)
    assert 'tcp dport { 80, 443, 8080 } accept comment "pw:excluded-ports"' in kept.script
    assert kept.script.index("pw:excluded-ports") < kept.script.index("pw:sooner")
    assert "pw:old" not in script
    assert script.index("pw:sooner") < script.index("pw:later")
    assert_safe_script(script)


def test_monitor_mode_warns_and_accepts():
    rendered = render_policy(_policy(mode="monitor"), utcnow())
    assert "policy accept;" in rendered.script
    assert rendered.warnings


def test_lockout_requires_phrase_for_unknown_client():
    risk, reason = evaluate_lockout(_policy(), "203.0.113.50")
    assert risk is True
    assert "203.0.113.50" not in reason or "drop" in reason or "Enforce" in reason
    safe, _ = evaluate_lockout(_policy(), "127.0.0.1")
    assert safe is False


def test_script_guard_rejects_other_tables():
    try:
        assert_safe_script("table inet filter {\n}\n")
    except ValueError as exc:
        assert "unexpected" in str(exc) or "port_warden" in str(exc)
    else:
        raise AssertionError("foreign table was accepted")


def test_ban_protected_address(auth):
    response = auth.post("/api/v1/bans", json={"ip": "127.0.0.1", "seconds": 60})
    assert response.status_code == 400

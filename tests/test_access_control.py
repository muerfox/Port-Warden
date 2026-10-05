from tests.conftest import PASSWORD, make_settings
from app.factory import create_app
from fastapi.testclient import TestClient


def test_health_has_no_secrets(client, settings):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    body = response.text
    assert settings.secret_key not in body
    assert PASSWORD not in body


def test_api_requires_auth(client):
    response = client.get("/api/v1/rules")
    assert response.status_code == 401


def test_login_and_csrf(client):
    denied = client.post(
        "/api/v1/rules",
        json={
            "name": "web",
            "action": "allow",
            "direction": "in",
            "protocol": "tcp",
            "ports": "443",
        },
    )
    assert denied.status_code == 401

    logged_in = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": PASSWORD},
    )
    assert logged_in.status_code == 200
    assert "password" not in logged_in.json()
    csrf = logged_in.json()["csrf_token"]

    missing = client.post(
        "/api/v1/rules",
        json={
            "name": "web",
            "action": "allow",
            "direction": "in",
            "protocol": "tcp",
            "ports": "443",
        },
    )
    assert missing.status_code == 403

    client.headers["X-CSRF-Token"] = csrf
    created = client.post(
        "/api/v1/rules",
        json={
            "name": "web",
            "action": "allow",
            "direction": "in",
            "protocol": "tcp",
            "ports": "443",
        },
    )
    assert created.status_code == 200
    assert created.json()["name"] == "web"


def test_login_rate_limit(tmp_path):
    app = create_app(make_settings(tmp_path, login_rate_limit=3, login_rate_window=300))
    with TestClient(app, client=("127.0.0.1", 9), follow_redirects=False) as client:
        for _ in range(3):
            response = client.post(
                "/api/v1/auth/login",
                json={"username": "admin", "password": "wrong-password-value"},
            )
            assert response.status_code == 401
            assert "wrong-password-value" not in response.text
        blocked = client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "wrong-password-value"},
        )
        assert blocked.status_code == 429


def test_failed_login_is_not_logged_with_password(client, tmp_path):
    client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "wrong-password-value"},
    )
    log_path = tmp_path / "logs" / "port-warden.jsonl"
    text = log_path.read_text(encoding="utf-8") if log_path.exists() else ""
    assert "wrong-password-value" not in text


def test_presets_do_not_open_ports(auth):
    presets = auth.get("/api/v1/presets")
    assert presets.status_code == 200
    assert any(item["id"] == "ssh" for item in presets.json()["presets"])
    rules = auth.get("/api/v1/rules")
    assert rules.json()["rules"] == []


def test_mfa_required_after_enable(auth):
    import pyotp

    setup = auth.post("/api/v1/auth/mfa/setup")
    assert setup.status_code == 200
    secret = setup.json()["secret"]
    code = pyotp.TOTP(secret).now()
    enabled = auth.post("/api/v1/auth/mfa/enable", json={"code": code})
    assert enabled.status_code == 200
    auth.post("/api/v1/auth/logout")
    auth.headers.pop("X-CSRF-Token", None)
    pending = auth.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": PASSWORD},
    )
    assert pending.status_code == 200
    assert pending.json()["mfa_required"] is True
    assert "pw_session" not in auth.cookies
    ok = auth.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": PASSWORD, "totp": pyotp.TOTP(secret).now()},
    )
    assert ok.status_code == 200
    assert "csrf_token" in ok.json()


def test_dashboard_login(client):
    page = client.get("/login")
    assert page.status_code == 200
    assert "Port Warden" in page.text
    signed = client.post("/login", data={"username": "admin", "password": PASSWORD})
    assert signed.status_code == 303
    home = client.get("/")
    assert home.status_code == 200
    assert "Host and gateway firewall" in home.text

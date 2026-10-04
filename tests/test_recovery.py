from fastapi.testclient import TestClient

from app.factory import create_app
from app.services.firewall.backend import NftError
from tests.conftest import PASSWORD, make_settings


class FakeBackend:
    name = "fake"

    def __init__(self) -> None:
        self.loaded = None
        self.fail_apply = 0
        self.fail_check = False
        self.calls: list[tuple[str, str]] = []

    def check(self, script: str) -> None:
        self.calls.append(("check", script))
        if self.fail_check:
            raise NftError("check failed")

    def apply(self, script: str) -> None:
        self.calls.append(("apply", script))
        if self.fail_apply:
            self.fail_apply -= 1
            raise NftError("apply failed")
        self.loaded = script

    def dump_table(self) -> str:
        return self.loaded or ""


def _login(client: TestClient) -> None:
    response = client.post("/api/v1/auth/login", json={"username": "admin", "password": PASSWORD})
    assert response.status_code == 200, response.text
    client.headers["X-CSRF-Token"] = response.json()["csrf_token"]


def test_startup_does_not_touch_firewall(tmp_path):
    backend = FakeBackend()
    app = create_app(make_settings(tmp_path), backend=backend)
    with TestClient(app, client=("127.0.0.1", 1), follow_redirects=False):
        pass
    assert backend.calls == []


def test_disabled_backend_stages_without_apply(auth, tmp_path):
    created = auth.post(
        "/api/v1/rules",
        json={"name": "https", "action": "allow", "direction": "in", "protocol": "tcp", "ports": "443"},
    )
    assert created.status_code == 200
    preview = auth.post("/api/v1/firewall/preview")
    assert preview.status_code == 200
    body = preview.json()
    assert body["enforces"] is False
    assert "policy drop;" in body["script"]
    applied = auth.post("/api/v1/firewall/apply", json={"confirm_token": body["confirm_token"]})
    assert applied.status_code == 200
    assert applied.json()["applied"] is False
    assert (tmp_path / "staged.nft").is_file()
    status = auth.get("/api/v1/firewall/status")
    assert status.json()["installed"] is False


def test_apply_failure_restores_last_good(tmp_path):
    backend = FakeBackend()
    app = create_app(make_settings(tmp_path), backend=backend)
    with TestClient(app, client=("127.0.0.1", 2), follow_redirects=False) as client:
        _login(client)
        first = client.post(
            "/api/v1/rules",
            json={"name": "https", "action": "allow", "direction": "in", "protocol": "tcp", "ports": "443"},
        )
        assert first.status_code == 200
        preview = client.post("/api/v1/firewall/preview")
        applied = client.post(
            "/api/v1/firewall/apply",
            json={"confirm_token": preview.json()["confirm_token"]},
        )
        assert applied.status_code == 200
        assert applied.json()["applied"] is True
        good = backend.loaded
        assert good and "pw:https" in good

        second = client.post(
            "/api/v1/rules",
            json={"name": "smtp", "action": "allow", "direction": "in", "protocol": "tcp", "ports": "25"},
        )
        assert second.status_code == 200
        backend.fail_apply = 1
        preview = client.post("/api/v1/firewall/preview")
        failed = client.post(
            "/api/v1/firewall/apply",
            json={"confirm_token": preview.json()["confirm_token"]},
        )
        assert failed.status_code == 502
        assert backend.loaded == good
        assert "pw:smtp" not in (backend.loaded or "")


def test_check_failure_does_not_replace_rules(tmp_path):
    backend = FakeBackend()
    app = create_app(make_settings(tmp_path), backend=backend)
    with TestClient(app, client=("127.0.0.1", 3), follow_redirects=False) as client:
        _login(client)
        client.post(
            "/api/v1/rules",
            json={"name": "https", "action": "allow", "direction": "in", "protocol": "tcp", "ports": "443"},
        )
        preview = client.post("/api/v1/firewall/preview")
        client.post("/api/v1/firewall/apply", json={"confirm_token": preview.json()["confirm_token"]})
        good = backend.loaded
        client.post(
            "/api/v1/rules",
            json={"name": "smtp", "action": "allow", "direction": "in", "protocol": "tcp", "ports": "25"},
        )
        backend.fail_check = True
        preview = client.post("/api/v1/firewall/preview")
        failed = client.post(
            "/api/v1/firewall/apply",
            json={"confirm_token": preview.json()["confirm_token"]},
        )
        assert failed.status_code == 502
        assert backend.loaded == good
        assert not any(name == "apply" and "pw:smtp" in script for name, script in backend.calls)


def test_lockout_phrase(tmp_path):
    app = create_app(make_settings(tmp_path))
    with TestClient(app, client=("203.0.113.50", 4), follow_redirects=False) as client:
        _login(client)
        preview = client.post("/api/v1/firewall/preview")
        assert preview.json()["lockout_risk"] is True
        blocked = client.post(
            "/api/v1/firewall/apply",
            json={"confirm_token": preview.json()["confirm_token"]},
        )
        assert blocked.status_code == 409
        allowed = client.post(
            "/api/v1/firewall/apply",
            json={
                "confirm_token": preview.json()["confirm_token"],
                "lockout_phrase": "I_UNDERSTAND_LOCKOUT",
            },
        )
        assert allowed.status_code == 200
        assert allowed.json()["lockout_override"] is True

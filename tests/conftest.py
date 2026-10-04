import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.factory import create_app

PASSWORD = "correct-horse-battery"


def make_settings(tmp_path, **overrides) -> Settings:
    values = {
        "secret_key": "test-secret-key-not-for-production",
        "admin_username": "admin",
        "admin_password": PASSWORD,
        "database_url": "sqlite:///:memory:",
        "data_dir": tmp_path,
        "nft_backend": "disabled",
        "bind_host": "127.0.0.1",
        "expose_public": False,
        "management_cidrs": ["127.0.0.1/32", "::1/128"],
        "cookie_secure": False,
        "auth_log_path": "",
        "ban_auto_apply": False,
    }
    values.update(overrides)
    return Settings(**values)


@pytest.fixture
def settings(tmp_path):
    return make_settings(tmp_path)


@pytest.fixture
def app(settings):
    return create_app(settings)


@pytest.fixture
def client(app):
    with TestClient(app, client=("127.0.0.1", 12345), follow_redirects=False) as test_client:
        yield test_client


@pytest.fixture
def auth(client):
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": PASSWORD},
    )
    assert response.status_code == 200, response.text
    token = response.json()["csrf_token"]
    client.headers["X-CSRF-Token"] = token
    return client

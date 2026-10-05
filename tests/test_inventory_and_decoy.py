import importlib.util
import socket
import threading
from pathlib import Path

import pytest

from app.__main__ import ssl_kwargs
from app.config import Settings
from app.services.inventory.ports import (
    check_reachability,
    classify_address,
    detect_ssh_ports,
    inventory_warning,
    parse_proc_net,
    parse_ss,
    service_label,
)
from app.services.inventory.workspace import (
    close_port,
    consolidate_listeners,
    effective_open_ports,
    effective_ssh_port,
    keep_port_open,
)


def test_ss_and_proc_classification():
    rows = parse_ss(
        "tcp LISTEN 0 128 127.0.0.1:8443 0.0.0.0:*\n"
        'tcp LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:(("sshd",pid=847,fd=3))\n'
        'tcp LISTEN 0 128 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=900,fd=6))\n'
        "tcp ESTAB 0 0 10.1.1.1:22 203.0.113.2:50000\n"
    )
    scopes = {(row["port"], row["scope"]) for row in rows}
    assert (8443, "local") in scopes
    assert (2222, "all_interfaces") in scopes
    assert all(row["port"] != 50000 for row in rows)
    by_port = {row["port"]: row for row in rows}
    assert by_port[2222]["process"] == "sshd"
    assert by_port[2222]["pid"] == 847
    assert by_port[2222]["service"] == "SSH"
    assert by_port[2222]["is_ssh"] is True
    assert by_port[80]["service"] == "HTTP"
    assert detect_ssh_ports(rows) == [2222]
    assert service_label("docker-proxy") == "Docker publish"
    assert effective_ssh_port(None, Settings(secret_key="x" * 16, ssh_port=22), rows) == 2222

    proc = (
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0\n"
        "   1: 08080808:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2 1 0000000000000000 100 0 0 10 0\n"
    )
    parsed = parse_proc_net(proc, ipv6=False)
    by_port = {row["port"]: row for row in parsed}
    assert by_port[22]["address"] == "127.0.0.1"
    assert by_port[22]["scope"] == "local"
    assert by_port[80]["address"] == "8.8.8.8"
    assert classify_address("8.8.8.8") == "public_address"
    assert classify_address("10.1.1.5") == "private_interface"


def test_reachability_is_allowlisted(tmp_path):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    port = sock.getsockname()[1]
    try:
        with pytest.raises(PermissionError):
            check_reachability("203.0.113.10", 80, [])
        result = check_reachability("127.0.0.1", port, [f"127.0.0.1:{port}"], timeout=1)
    finally:
        sock.close()
    assert result["tcp_connect"] is True
    assert "not proof" in result["note"]


def test_tls_is_off_unless_both_files_are_set():
    assert ssl_kwargs(Settings(secret_key="x" * 16, ssl_certfile="", ssl_keyfile="")) == {}
    with pytest.raises(RuntimeError):
        ssl_kwargs(Settings(secret_key="x" * 16, ssl_certfile="/cert.pem", ssl_keyfile=""))
    assert ssl_kwargs(Settings(secret_key="x" * 16, ssl_certfile="/cert.pem", ssl_keyfile="/key.pem")) == {
        "ssl_certfile": "/cert.pem",
        "ssl_keyfile": "/key.pem",
    }


def test_public_bind_requires_explicit_flag():
    with pytest.raises(RuntimeError):
        Settings(bind_host="0.0.0.0", expose_public=False, secret_key="x" * 16).assert_safe_bind()
    Settings(bind_host="192.168.1.10", expose_public=False, secret_key="x" * 16).assert_safe_bind()
    Settings(bind_host="0.0.0.0", expose_public=True, secret_key="x" * 16).assert_safe_bind()


def test_csv_list_env_vars(monkeypatch):
    monkeypatch.setenv("PORT_WARDEN_MANAGEMENT_CIDRS", "127.0.0.1/32,::1/128")
    monkeypatch.setenv("PORT_WARDEN_REACHABILITY_TARGETS", "")
    monkeypatch.setenv("PORT_WARDEN_ADMIN_PASSWORD", "x")
    settings = Settings()
    assert settings.management_cidrs == ["127.0.0.1/32", "::1/128"]
    assert settings.reachability_targets == []
    assert settings.excluded_ports == []
    monkeypatch.setenv("PORT_WARDEN_EXCLUDED_PORTS", "80,443")
    assert Settings().excluded_ports == [80, 443]
    warn = inventory_warning(host_network=False, nft_backend="disabled")
    assert "not in the host network" in warn
    host_warn = inventory_warning(host_network=True, nft_backend="local", host_pid=True)
    assert "Host network and host PID" in host_warn
    monkeypatch.setattr(
        "app.services.inventory.ports.host_pid_namespace",
        lambda: False,
    )
    pid_warn = inventory_warning(host_network=True, nft_backend="local", host_pid=False)
    assert "container PID" in pid_warn


def test_ports_panel_keeps_discovered_ports(settings, app):
    settings.bind_port = 9090
    db = app.state.session_factory()
    try:
        assert effective_open_ports(db, settings) == [9090]
        keep_port_open(db, settings, 2222)
        keep_port_open(db, settings, 443)
        db.commit()
        assert effective_open_ports(db, settings) == [443, 2222, 9090]
        close_port(db, settings, 443)
        db.commit()
        assert effective_open_ports(db, settings) == [2222, 9090]
        with pytest.raises(ValueError):
            close_port(db, settings, 9090)
        merged = consolidate_listeners(
            [
                {
                    "protocol": "tcp",
                    "address": "0.0.0.0",
                    "port": 2222,
                    "scope": "all_interfaces",
                    "scope_label": "all",
                    "possibly_public": True,
                },
                {
                    "protocol": "tcp",
                    "address": "::",
                    "port": 2222,
                    "scope": "all_interfaces",
                    "scope_label": "all",
                    "possibly_public": True,
                },
            ]
        )
        assert len(merged) == 1
        assert merged[0]["port"] == 2222
    finally:
        db.close()


def test_ports_panel_actions_via_ui(auth, app):
    app.state.settings.bind_port = 9090
    page = auth.get("/ports")
    assert page.status_code == 200
    assert b"Service" in page.content
    assert b"Process" in page.content
    keep = auth.post("/ports/keep-open", data={"port": "2222", "csrf_token": auth.headers["X-CSRF-Token"]})
    assert keep.status_code in {302, 303}
    db = app.state.session_factory()
    try:
        assert 2222 in effective_open_ports(db, app.state.settings)
    finally:
        db.close()


def _load_decoy():
    path = Path(__file__).resolve().parents[1] / "honeypots" / "decoy.py"
    spec = importlib.util.spec_from_file_location("port_warden_decoy", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_decoy_does_not_execute_or_connect():
    source = (Path(__file__).resolve().parents[1] / "honeypots" / "decoy.py").read_text(encoding="utf-8")
    assert "subprocess" not in source
    assert ".connect(" not in source
    decoy = _load_decoy()
    assert "redacted" in decoy.summarize_http(b"GET /admin?token=secret HTTP/1.1\r\n")
    left, right = socket.socketpair()
    holder = {}

    def run():
        decoy.handle_ssh(left, ("203.0.113.9", 1111))
        left.close()

    thread = threading.Thread(target=run)
    thread.start()
    banner = right.recv(128)
    right.sendall(b"SSH-2.0-client\r\n")
    thread.join(2)
    right.close()
    assert banner.startswith(b"SSH-2.0-PortWarden-Decoy")
    assert holder == {}

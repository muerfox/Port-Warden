from app.services.firewall.render import GatewayPolicy, render_policy, validate_iface
from app.services.firewall.safeguard import evaluate_lockout
from app.services.firewall.script_guard import assert_safe_script
from app.services.gateway.failover import desired_active_wan
from app.services.gateway.ips import parse_eve_alert
from app.services.gateway.routes import policy_commands
from app.services.gateway.sysctl import enable_forwarding, restore_forwarding
from app.services.gateway.wireguard import render_client_config
from app.timeutil import utcnow
from tests.test_validation import _policy

_PRIVATE = "A" * 43 + "="
_PUBLIC = "B" * 43 + "="


def test_host_policy_has_no_forward_chain():
    script = render_policy(_policy(), utcnow()).script
    assert "hook forward" not in script
    assert "masquerade" not in script


def test_gateway_render_forwards_and_nats():
    policy = _policy(
        gateway=GatewayPolicy(
            enabled=True,
            lan_ifaces=["eth1"],
            wan_iface="eth0",
            wan_backup_iface="eth2",
            active_wan="primary",
            nat_enabled=True,
            wg_enabled=True,
            ips_enabled=True,
            ips_queue=0,
        )
    )
    rendered = render_policy(policy, utcnow())
    script = rendered.script
    assert "type filter hook forward priority 0; policy drop;" in script
    assert 'iifname { "eth1", "wg0" } oifname "eth0" meta mark set 0x7077 accept comment "pw:lan-wan"' in script
    assert 'iifname "eth0" ct state new queue num 0 comment "pw:ips"' in script
    assert 'masquerade comment "pw:nat"' in script
    assert "ip_forward is set to 1 only after a successful Apply" in " ".join(rendered.warnings)
    assert_safe_script(script)


def test_backup_wan_is_used_when_selected():
    policy = _policy(
        gateway=GatewayPolicy(
            enabled=True,
            lan_ifaces=["eth1"],
            wan_iface="eth0",
            wan_backup_iface="eth2",
            active_wan="backup",
            nat_enabled=True,
        )
    )
    script = render_policy(policy, utcnow()).script
    assert 'oifname "eth2"' in script
    assert 'oifname "eth0"' not in script


def test_incomplete_gateway_is_a_lockout():
    policy = _policy(gateway=GatewayPolicy(enabled=True))
    risk, reason = evaluate_lockout(policy, "127.0.0.1")
    assert risk is True
    assert "LAN path" in reason


def test_failover_choice_and_route_commands():
    assert desired_active_wan(primary_up=True, backup_iface="eth2") == "primary"
    assert desired_active_wan(primary_up=False, backup_iface="eth2") == "backup"
    assert desired_active_wan(primary_up=False, backup_iface="") == "primary"
    gateway = GatewayPolicy(
        enabled=True,
        lan_ifaces=["eth1"],
        wan_iface="eth0",
        wan_backup_iface="eth2",
        active_wan="backup",
        nat_enabled=True,
    )
    commands = policy_commands(gateway, "203.0.113.1", "198.51.100.1", "ip")
    assert ["ip", "route", "replace", "default", "via", "198.51.100.1", "dev", "eth2", "table", "77"] in commands


def test_eve_alert_parse():
    line = (
        '{"timestamp":"2026-10-05T00:00:00.000000+0000","event_type":"alert",'
        '"src_ip":"203.0.113.9","dest_port":443,"alert":{"signature":"ET SCAN"}}'
    )
    parsed = parse_eve_alert(line)
    assert parsed["src_ip"] == "203.0.113.9"
    assert parsed["dst_port"] == 443
    assert parsed["signature"] == "ET SCAN"
    assert parse_eve_alert('{"event_type":"stats"}') is None


def test_forwarding_restores_previous_values(tmp_path, monkeypatch):
    store = {"net.ipv4.ip_forward": "0", "net.ipv6.conf.all.forwarding": "0"}

    def read(key):
        return store[key]

    def write(key, value):
        store[key] = value

    monkeypatch.setattr("app.services.gateway.sysctl.read_sysctl", read)
    monkeypatch.setattr("app.services.gateway.sysctl.write_sysctl", write)
    from app.config import Settings

    settings = Settings(data_dir=tmp_path, admin_password="x")
    enable_forwarding(settings)
    assert store["net.ipv4.ip_forward"] == "1"
    restore_forwarding(settings)
    assert store["net.ipv4.ip_forward"] == "0"
    assert store["net.ipv6.conf.all.forwarding"] == "0"


def test_gateway_page_and_one_time_peer_config(auth, monkeypatch):
    monkeypatch.setattr(
        "app.services.gateway.wireguard.generate_keypair",
        lambda wg_bin="wg": (_PRIVATE, _PUBLIC),
    )
    monkeypatch.setattr(
        "app.services.gateway.state.list_interfaces",
        lambda ip_bin="ip": ["eth0", "eth1"],
    )
    page = auth.get("/gateway")
    assert page.status_code == 200
    assert b"Enable gateway" in page.content
    token = auth.headers["X-CSRF-Token"]
    saved = auth.post(
        "/gateway",
        data={
            "csrf_token": token,
            "gateway_enabled": "yes",
            "nat_enabled": "yes",
            "wg_enabled": "yes",
            "wan_iface": "eth0",
            "wan_backup_iface": "eth2",
            "lan_ifaces": "eth1",
            "wan_gateway": "203.0.113.1",
            "wan_backup_gateway": "198.51.100.1",
            "wg_port": "51820",
            "wg_address": "10.77.0.1/24",
        },
    )
    assert saved.status_code == 303
    created = auth.post(
        "/gateway/peers",
        data={"csrf_token": token, "name": "laptop", "allowed_ips": "10.77.0.2/32"},
    )
    assert created.status_code == 303
    listed = auth.get("/gateway")
    assert b"laptop" in listed.content
    downloaded = auth.post("/gateway/peers/1/config", data={"csrf_token": token})
    assert downloaded.status_code == 200
    assert b"PrivateKey = " in downloaded.content
    assert b"ENDPOINT_HOST:51820" in downloaded.content
    again = auth.post("/gateway/peers/1/config", data={"csrf_token": token})
    assert again.status_code == 303
    assert validate_iface("eth0") == "eth0"
    text = render_client_config(_PRIVATE, "10.77.0.2/32", _PUBLIC, 51820, "0.0.0.0/0")
    assert "PublicKey = " in text


def test_status_shows_gateway(auth):
    page = auth.get("/")
    assert page.status_code == 200
    assert b"Gateway" in page.content
    assert b"IPS alerts" in page.content

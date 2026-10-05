from __future__ import annotations

import ipaddress
import re
import subprocess

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings
from app.models import WgPeer
from app.services.firewall.engine import get_setting
from app.services.gateway.state import WG_IFACE
from app.timeutil import utcnow

_KEY = re.compile(r"^[A-Za-z0-9+/]{42,44}={0,2}$")
_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")


def validate_key(value: str) -> str:
    text = (value or "").strip()
    if not _KEY.match(text):
        raise ValueError("invalid WireGuard key")
    return text


def validate_peer_name(name: str) -> str:
    text = (name or "").strip().lower()
    if not _NAME.match(text):
        raise ValueError("peer name must be lowercase letters, digits, and hyphens")
    return text


def validate_allowed_ips(value: str) -> str:
    parts = [part.strip() for part in (value or "").split(",") if part.strip()]
    if not parts:
        raise ValueError("allowed IPs are required")
    networks = [str(ipaddress.ip_network(part, strict=False)) for part in parts]
    return ", ".join(networks)


def _run(command: list[str], stdin: str | None = None) -> str:
    try:
        completed = subprocess.run(
            command,
            input=stdin,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"command failed: {command[0]}") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "command failed").strip()
        raise RuntimeError(detail[:300])
    return completed.stdout.strip()


def generate_keypair(wg_bin: str = "wg") -> tuple[str, str]:
    private = validate_key(_run([wg_bin, "genkey"]))
    public = validate_key(_run([wg_bin, "pubkey"], stdin=private + "\n"))
    return private, public


def ensure_server_keys(settings: Settings) -> tuple[str, str]:
    directory = settings.data_dir / "wireguard"
    directory.mkdir(parents=True, exist_ok=True)
    private_path = directory / "server.key"
    public_path = directory / "server.pub"
    if private_path.is_file() and public_path.is_file():
        return (
            validate_key(private_path.read_text(encoding="utf-8")),
            validate_key(public_path.read_text(encoding="utf-8")),
        )
    private, public = generate_keypair(settings.wg_bin)
    private_path.write_text(private + "\n", encoding="utf-8")
    public_path.write_text(public + "\n", encoding="utf-8")
    private_path.chmod(0o600)
    public_path.chmod(0o600)
    return private, public


def render_client_config(
    client_private: str,
    client_address: str,
    server_public: str,
    listen_port: int,
    allowed_ips: str,
) -> str:
    address = client_address.strip()
    if "/" not in address:
        address = f"{address}/32"
    return (
        "[Interface]\n"
        f"PrivateKey = {client_private.strip()}\n"
        f"Address = {address}\n"
        "\n"
        "[Peer]\n"
        f"PublicKey = {server_public.strip()}\n"
        f"Endpoint = ENDPOINT_HOST:{int(listen_port)}\n"
        f"AllowedIPs = {allowed_ips.strip()}\n"
        "PersistentKeepalive = 25\n"
    )


def client_config_text(db: Session, settings: Settings, peer: WgPeer) -> str:
    if not peer.client_private:
        raise ValueError("client private key was already downloaded")
    _private, public = ensure_server_keys(settings)
    port = int(get_setting(db, "wg_port", "51820") or "51820")
    first = peer.allowed_ips.split(",")[0].strip()
    return render_client_config(peer.client_private, first, public, port, peer.allowed_ips)


def add_peer(db: Session, settings: Settings, name: str, allowed_ips: str) -> WgPeer:
    peer_name = validate_peer_name(name)
    cidrs = validate_allowed_ips(allowed_ips)
    if db.scalars(select(WgPeer).where(WgPeer.name == peer_name)).first() is not None:
        raise ValueError("peer name already exists")
    private, public = generate_keypair(settings.wg_bin)
    peer = WgPeer(
        name=peer_name,
        public_key=public,
        allowed_ips=cidrs,
        client_private=private,
        created_at=utcnow(),
    )
    db.add(peer)
    db.flush()
    return peer


def sync_interface(db: Session, settings: Settings) -> None:
    private, _public = ensure_server_keys(settings)
    directory = settings.data_dir / "wireguard"
    key_path = directory / "server.key"
    key_path.write_text(private + "\n", encoding="utf-8")
    key_path.chmod(0o600)
    port = int(get_setting(db, "wg_port", "51820") or "51820")
    address = get_setting(db, "wg_address", "10.77.0.1/24") or "10.77.0.1/24"
    ipaddress.ip_interface(address)
    link = subprocess.run(
        [settings.ip_bin, "link", "show", WG_IFACE],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    if link.returncode != 0:
        _run([settings.ip_bin, "link", "add", WG_IFACE, "type", "wireguard"])
    _run([settings.wg_bin, "set", WG_IFACE, "listen-port", str(port), "private-key", str(key_path)])
    peers = db.scalars(select(WgPeer).order_by(WgPeer.id)).all()
    for peer in peers:
        allowed = [part.strip() for part in peer.allowed_ips.split(",") if part.strip()]
        _run([settings.wg_bin, "set", WG_IFACE, "peer", peer.public_key, "allowed-ips", ",".join(allowed)])
    addr = subprocess.run(
        [settings.ip_bin, "addr", "replace", address, "dev", WG_IFACE],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    if addr.returncode != 0:
        raise RuntimeError((addr.stderr or "failed to add wg0 address").strip()[:300])
    _run([settings.ip_bin, "link", "set", WG_IFACE, "up"])

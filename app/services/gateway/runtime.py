from __future__ import annotations

import shutil
from pathlib import Path

from sqlalchemy.orm import Session

from app.config import Settings
from app.services.firewall.engine import get_setting
from app.services.firewall.render import Policy
from app.services.gateway.ips import assert_ips_ready, start_suricata, stop_suricata
from app.services.gateway.routes import install_policy_route, remove_policy_route
from app.services.gateway.sysctl import enable_forwarding, restore_forwarding
from app.services.gateway.wireguard import sync_interface


def _executable(binary: str) -> bool:
    path = Path(binary)
    if path.is_file():
        return True
    return shutil.which(binary) is not None


def assert_gateway_ready(settings: Settings, policy: Policy) -> None:
    """Refuse Apply that would blackhole traffic or start forwarding without tools."""
    gateway = policy.gateway
    if not gateway.enabled:
        return
    if gateway.ips_enabled:
        assert_ips_ready(settings)
    if not _executable(settings.ip_bin):
        raise ValueError("Gateway mode needs the ip command")
    if gateway.wg_enabled and not _executable(settings.wg_bin):
        raise ValueError("WireGuard is enabled but wg is not installed")


def sync_applied_state(
    settings: Settings,
    db: Session,
    policy: Policy,
    script: str,
    *,
    enforces: bool,
) -> None:
    if not enforces:
        return
    forwarding = "type filter hook forward" in script
    if not forwarding:
        stop_suricata(settings)
        remove_policy_route(settings)
        restore_forwarding(settings)
        return
    if policy.gateway.ips_enabled:
        start_suricata(settings)
    else:
        stop_suricata(settings)
    enable_forwarding(settings)
    install_policy_route(
        settings,
        policy.gateway,
        get_setting(db, "wan_gateway", "") or "",
        get_setting(db, "wan_backup_gateway", "") or "",
    )
    if policy.gateway.wg_enabled:
        sync_interface(db, settings)

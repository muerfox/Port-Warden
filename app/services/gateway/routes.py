from __future__ import annotations

import ipaddress
import subprocess

from app.config import Settings
from app.services.firewall.render import GatewayPolicy, active_wan_iface
from app.services.gateway.state import FWMARK, ROUTE_TABLE

# ip-rule priority owned by Port Warden. Removed on rollback.
RULE_PRIORITY = "100"


def _gateway_ip(policy: GatewayPolicy, primary: str, backup: str) -> str:
    if policy.active_wan == "backup" and policy.wan_backup_iface:
        return backup
    return primary


def policy_commands(policy: GatewayPolicy, primary_gateway: str, backup_gateway: str, ip_bin: str) -> list[list[str]]:
    """Build ip(8) commands for fwmark 0x7077. Hostnames are rejected."""
    iface = active_wan_iface(policy)
    gateway = _gateway_ip(policy, primary_gateway.strip(), backup_gateway.strip())
    if not policy.enabled or not iface or not gateway:
        return remove_commands(ip_bin)
    ipaddress.ip_address(gateway)
    return [
        [ip_bin, "rule", "del", "fwmark", FWMARK, "lookup", ROUTE_TABLE, "priority", RULE_PRIORITY],
        [ip_bin, "rule", "add", "fwmark", FWMARK, "lookup", ROUTE_TABLE, "priority", RULE_PRIORITY],
        [ip_bin, "route", "replace", "default", "via", gateway, "dev", iface, "table", ROUTE_TABLE],
    ]


def remove_commands(ip_bin: str) -> list[list[str]]:
    return [
        [ip_bin, "rule", "del", "fwmark", FWMARK, "lookup", ROUTE_TABLE, "priority", RULE_PRIORITY],
        [ip_bin, "route", "flush", "table", ROUTE_TABLE],
    ]


def apply_commands(commands: list[list[str]]) -> None:
    for command in commands:
        deleting = len(command) > 2 and command[2] == "del"
        flushing = "flush" in command
        try:
            completed = subprocess.run(command, capture_output=True, text=True, timeout=5, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            if deleting or flushing:
                continue
            raise RuntimeError(str(exc)) from exc
        if completed.returncode != 0 and not (deleting or flushing):
            detail = (completed.stderr or completed.stdout or "ip failed").strip()
            raise RuntimeError(detail[:300])


def install_policy_route(settings: Settings, policy: GatewayPolicy, primary_gateway: str, backup_gateway: str) -> None:
    apply_commands(policy_commands(policy, primary_gateway, backup_gateway, settings.ip_bin))


def remove_policy_route(settings: Settings) -> None:
    apply_commands(remove_commands(settings.ip_bin))

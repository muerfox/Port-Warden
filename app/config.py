from __future__ import annotations

import ipaddress
import os
from pathlib import Path
from typing import Annotated, Literal

import yaml
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

DEFAULT_SECRET = "change-me-in-production-use-long-random"


def _csv(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [part.strip() for part in str(value).split(",") if part.strip()]


def _port_list(value: object) -> list[int]:
    ports: list[int] = []
    for item in _csv(value):
        port = int(item)
        if not 1 <= port <= 65535:
            raise ValueError(f"port {port} out of range")
        if port not in ports:
            ports.append(port)
    return ports


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="PORT_WARDEN_",
        env_file=".env",
        extra="ignore",
    )

    secret_key: str = DEFAULT_SECRET
    admin_username: str = "admin"
    admin_password: str = ""
    bind_host: str = "127.0.0.1"
    bind_port: int = 8443
    expose_public: bool = False
    cookie_secure: bool = False
    ssl_certfile: str = ""
    ssl_keyfile: str = ""
    # Reinstall the last confirmed nftables table when this process starts.
    # No-op until an administrator has applied once. Does not invent a new policy.
    restore_on_start: bool = True
    session_hours: int = 12
    database_url: str = "sqlite:///./data/port-warden.sqlite"
    data_dir: Path = Path("./data")

    nft_backend: Literal["disabled", "local", "agent"] = "disabled"
    nft_bin: str = "nft"
    # True when the process shares the host network namespace (Compose host mode).
    host_network: bool = False
    # True when the process shares the host PID namespace (Compose pid: host).
    # Needed so Ports shows host sshd/nginx/… instead of container python.
    host_pid: bool = False
    agent_socket: str = "/run/port-warden/apply.sock"
    agent_token_file: str = "/etc/port-warden/agent.token"

    firewall_mode: Literal["enforce", "monitor"] = "enforce"
    # NoDecode: env is CSV (127.0.0.1/32,::1/128), not JSON. Without it,
    # pydantic-settings fails before the CSV validator runs.
    management_cidrs: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["127.0.0.1/32", "::1/128"]
    )
    # Optional first-run seed only. Prefer choosing open ports in the Ports panel.
    # The UI bind_port is always kept open even when this list is empty.
    excluded_ports: Annotated[list[int], NoDecode] = Field(default_factory=list)
    ssh_port: int = 22

    log_retention_days: int = 30
    log_max_bytes: int = 5_000_000

    bf_threshold: int = 5
    bf_window_seconds: int = 600
    bf_ban_seconds: int = 3600
    bf_cooldown_seconds: int = 600
    bf_permanent_after: int = 0
    auth_log_path: str = ""
    # Optional host syslog/kern log containing nft lines with prefix pw:drop.
    # Compose can mount host /var/log at /var/log/host. Probe sets work without this.
    nft_log_path: str = ""
    probe_poll_seconds: int = 30
    ban_auto_apply: bool = False
    suricata_bin: str = "suricata"
    suricata_rules: str = ""
    wg_bin: str = "wg"
    ip_bin: str = "ip"
    ping_bin: str = "ping"
    failover_seconds: int = 15

    reachability_targets: Annotated[list[str], NoDecode] = Field(default_factory=list)
    login_rate_limit: int = 5
    login_rate_window: int = 300

    @field_validator("management_cidrs", "reachability_targets", mode="before")
    @classmethod
    def _split_csv(cls, value: object) -> list[str]:
        return _csv(value)

    @field_validator("excluded_ports", mode="before")
    @classmethod
    def _split_ports(cls, value: object) -> list[int]:
        return _port_list(value)

    @field_validator("ssh_port")
    @classmethod
    def _port(cls, value: int) -> int:
        if not 1 <= value <= 65535:
            raise ValueError("ssh_port out of range")
        return value

    def assert_safe_bind(self) -> None:
        if self.expose_public:
            return
        host = self.bind_host.strip()
        if host == "localhost":
            return
        try:
            ip = ipaddress.ip_address(host)
        except ValueError as exc:
            raise RuntimeError(
                f"Refusing bind host {host!r}. Use a loopback or private address, "
                "or set expose_public for an explicit published management interface."
            ) from exc
        if ip.is_unspecified or ip.is_multicast:
            raise RuntimeError(
                "Refusing to bind a wildcard or multicast address without expose_public=true."
            )
        if ip.is_loopback or ip.is_private or ip.is_link_local:
            return
        raise RuntimeError(
            "Refusing to bind a public address without expose_public=true."
        )


def load_settings(config_path: str | None = None) -> Settings:
    """YAML fills defaults. Environment variables win."""
    path = Path(config_path) if config_path else None
    file_values: dict = {}
    if path and path.is_file():
        loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(loaded, dict):
            raise RuntimeError("config file must be a mapping")
        file_values = loaded
    filtered = {}
    for key, value in file_values.items():
        if f"PORT_WARDEN_{str(key).upper()}" not in os.environ:
            filtered[key] = value
    return Settings(**filtered)

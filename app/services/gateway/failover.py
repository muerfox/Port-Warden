from __future__ import annotations

import ipaddress
import subprocess
import threading

from sqlalchemy.orm import sessionmaker

from app.config import Settings
from app.logging_json import JsonLogger
from app.services.events import record_event
from app.services.firewall.engine import FirewallEngine, get_setting, script_sha, set_setting
from app.services.gateway.runtime import sync_applied_state


def gateway_reachable(ip: str, ping_bin: str = "ping") -> bool:
    """ICMP echo one literal gateway address. Hostnames are refused."""
    text = (ip or "").strip()
    if not text:
        return True
    ipaddress.ip_address(text)
    try:
        completed = subprocess.run(
            [ping_bin, "-c", "1", "-W", "2", text],
            capture_output=True,
            text=True,
            timeout=4,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0


def desired_active_wan(*, primary_up: bool, backup_iface: str) -> str:
    if primary_up or not backup_iface:
        return "primary"
    return "backup"


class FailoverPoller:
    def __init__(
        self,
        session_factory: sessionmaker,
        settings: Settings,
        engine: FirewallEngine,
        logger: JsonLogger,
    ) -> None:
        self.session_factory = session_factory
        self.settings = settings
        self.engine = engine
        self.logger = logger
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="port-warden-failover", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def _run(self) -> None:
        interval = max(5, int(self.settings.failover_seconds))
        while not self._stop.is_set():
            session = self.session_factory()
            try:
                self._tick(session)
                session.commit()
            except Exception:
                session.rollback()
                self.logger.emit("wan_failover_error", action="skip", src_ip="", dst_port="", rule_id="")
            finally:
                session.close()
            self._stop.wait(interval)

    def _tick(self, session) -> None:
        policy = self.engine.load_policy(session)
        gateway = policy.gateway
        if not gateway.enabled or not gateway.wan_iface:
            return
        primary_gateway = get_setting(session, "wan_gateway", "") or ""
        up = gateway_reachable(primary_gateway, self.settings.ping_bin)
        desired = desired_active_wan(primary_up=up, backup_iface=gateway.wan_backup_iface)
        current = get_setting(session, "active_wan", "primary") or "primary"
        if desired == current:
            return
        set_setting(session, "active_wan", desired)
        iface = gateway.wan_backup_iface if desired == "backup" else gateway.wan_iface
        record_event(
            session,
            self.logger,
            "wan_failover",
            action=desired,
            details={"iface": iface, "primary_up": up},
        )
        if not self.engine.enforces:
            return
        rendered = self.engine.render(session)
        self.engine.push(rendered.script)
        sync_applied_state(self.settings, session, self.engine.load_policy(session), rendered.script, enforces=True)
        digest = script_sha(rendered.script)
        self.engine._save_snapshot(session, rendered.script, digest, True, "wan-failover")

from __future__ import annotations

import json
import socket
import subprocess
from pathlib import Path

from app.services.firewall.script_guard import assert_safe_script, script_for_host


class NftError(Exception):
    pass


class DisabledBackend:
    """Stages rules in the app database only. Does not call nft."""

    name = "disabled"

    def check(self, script: str) -> None:
        assert_safe_script(script)

    def apply(self, script: str) -> None:
        raise NftError("nft backend is disabled; the ruleset was not installed on the host")

    def dump_table(self) -> str | None:
        return None


class LocalBackend:
    """Calls the nft binary. Requires CAP_NET_ADMIN in the host network namespace."""

    name = "local"

    def __init__(self, nft_bin: str = "nft") -> None:
        self.nft_bin = nft_bin

    def check(self, script: str) -> None:
        assert_safe_script(script)
        self._run(["-c", "-f", "-"], script_for_host(script, self._table_exists()))

    def apply(self, script: str) -> None:
        assert_safe_script(script)
        self._run(["-f", "-"], script_for_host(script, self._table_exists()))

    def _table_exists(self) -> bool:
        try:
            self._run(["list", "table", "inet", "port_warden"], None)
        except NftError:
            return False
        return True

    def dump_table(self) -> str | None:
        try:
            return self._run(["list", "table", "inet", "port_warden"], None)
        except NftError as exc:
            text = str(exc).lower()
            if "no such file" in text or "does not exist" in text or "not found" in text:
                return ""
            raise

    def list_set_json(self, set_name: str) -> dict | None:
        """Return JSON for one set in table inet port_warden, or None if missing."""
        if not set_name.replace("_", "").isalnum():
            raise NftError("invalid set name")
        try:
            raw = self._run(["-j", "list", "set", "inet", "port_warden", set_name], None)
        except NftError as exc:
            text = str(exc).lower()
            if "no such file" in text or "does not exist" in text or "not found" in text:
                return None
            raise
        try:
            return json.loads(raw) if raw.strip() else None
        except json.JSONDecodeError as exc:
            raise NftError("invalid nft JSON") from exc

    def _run(self, args: list[str], script: str | None) -> str:
        try:
            completed = subprocess.run(
                [self.nft_bin, *args],
                input=script,
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )
        except FileNotFoundError as exc:
            raise NftError(f"nft binary not found: {self.nft_bin}") from exc
        except subprocess.TimeoutExpired as exc:
            raise NftError("nft command timed out") from exc
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or "nft failed").strip()
            raise NftError(detail[:500])
        return completed.stdout


class AgentBackend:
    """Sends a script to the root-only host agent over a unix socket."""

    name = "agent"

    def __init__(self, socket_path: str, token: str) -> None:
        self.socket_path = socket_path
        self.token = token

    def check(self, script: str) -> None:
        assert_safe_script(script)
        self._rpc("check", script)

    def apply(self, script: str) -> None:
        assert_safe_script(script)
        self._rpc("apply", script)

    def dump_table(self) -> str | None:
        response = self._rpc("dump", "")
        return response.get("dump")

    def _rpc(self, op: str, script: str) -> dict:
        payload = json.dumps({"op": op, "token": self.token, "script": script}) + "\n"
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(30)
        try:
            sock.connect(self.socket_path)
            sock.sendall(payload.encode("utf-8"))
            data = b""
            while b"\n" not in data:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
                if len(data) > 1_000_000:
                    raise NftError("agent response too large")
        except OSError as exc:
            raise NftError(f"nft agent unavailable: {exc}") from exc
        finally:
            sock.close()
        if not data:
            raise NftError("empty response from nft agent")
        try:
            response = json.loads(data.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise NftError("invalid response from nft agent") from exc
        if not response.get("ok"):
            raise NftError(str(response.get("error") or "agent rejected the ruleset")[:500])
        return response


def load_agent_token(path: str) -> str:
    file_path = Path(path)
    if not file_path.is_file():
        raise RuntimeError(f"agent token file not found: {path}")
    mode = file_path.stat().st_mode & 0o077
    if mode:
        raise RuntimeError(f"agent token file {path} must not be group- or world-readable")
    token = file_path.read_text(encoding="utf-8").strip()
    if len(token) < 16:
        raise RuntimeError("agent token is too short")
    return token

#!/usr/bin/env python3
"""Root helper that applies only the Port Warden nftables table.

The web app does not need CAP_NET_ADMIN when this agent is used.
Keep the token file mode 0600 and the socket group-restricted.
"""

from __future__ import annotations

import argparse
import hmac
import json
import os
import socket
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.firewall.script_guard import assert_safe_script, script_for_host  # noqa: E402


def run_nft(nft_bin: str, args: list[str], script: str | None) -> str:
    completed = subprocess.run(
        [nft_bin, *args],
        input=script,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "nft failed").strip()
        raise RuntimeError(detail[:500])
    return completed.stdout


def process_request(message: dict, token: str, state_dir: Path, nft_bin: str) -> dict:
    supplied = str(message.get("token", ""))
    if not hmac.compare_digest(supplied, token):
        return {"ok": False, "error": "unauthorized"}
    op = message.get("op")
    script = str(message.get("script", ""))
    last_good = state_dir / "last-good.nft"
    try:
        if op == "dump":
            try:
                dump = run_nft(nft_bin, ["list", "table", "inet", "port_warden"], None)
            except RuntimeError as exc:
                text = str(exc).lower()
                if "does not exist" in text or "no such file" in text or "not found" in text:
                    dump = ""
                else:
                    raise
            return {"ok": True, "dump": dump}
        assert_safe_script(script)
        exists = True
        try:
            run_nft(nft_bin, ["list", "table", "inet", "port_warden"], None)
        except RuntimeError:
            exists = False
        prepared = script_for_host(script, exists)
        if op == "check":
            run_nft(nft_bin, ["-c", "-f", "-"], prepared)
            return {"ok": True}
        if op == "apply":
            run_nft(nft_bin, ["-c", "-f", "-"], prepared)
            try:
                run_nft(nft_bin, ["-f", "-"], prepared)
            except RuntimeError as exc:
                if last_good.is_file():
                    previous = last_good.read_text(encoding="utf-8")
                    run_nft(nft_bin, ["-f", "-"], previous)
                    return {"ok": False, "error": f"apply failed; previous ruleset restored: {exc}"}
                return {"ok": False, "error": f"apply failed; host ruleset unchanged: {exc}"}
            last_good.write_text(prepared, encoding="utf-8")
            return {"ok": True}
        return {"ok": False, "error": "unknown operation"}
    except (RuntimeError, ValueError) as exc:
        return {"ok": False, "error": str(exc)[:500]}


def serve(socket_path: str, token: str, state_dir: Path, nft_bin: str) -> None:
    path = Path(socket_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    os.chmod(path, 0o660)
    server.listen(8)
    while True:
        conn, _addr = server.accept()
        with conn:
            data = b""
            while b"\n" not in data:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                data += chunk
                if len(data) > 300_000:
                    break
            try:
                message = json.loads(data.decode("utf-8"))
            except json.JSONDecodeError:
                response = {"ok": False, "error": "invalid request"}
            else:
                response = process_request(message, token, state_dir, nft_bin)
            conn.sendall((json.dumps(response) + "\n").encode("utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(description="Port Warden nftables agent")
    parser.add_argument("--socket", default="/run/port-warden/apply.sock")
    parser.add_argument("--token-file", default="/etc/port-warden/agent.token")
    parser.add_argument("--state-dir", default="/var/lib/port-warden")
    parser.add_argument("--nft-bin", default="nft")
    args = parser.parse_args()
    token_path = Path(args.token_file)
    if not token_path.is_file():
        raise SystemExit(f"token file not found: {token_path}")
    if token_path.stat().st_mode & 0o077:
        raise SystemExit("token file must be mode 0600")
    token = token_path.read_text(encoding="utf-8").strip()
    if len(token) < 16:
        raise SystemExit("token is too short")
    state_dir = Path(args.state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    serve(args.socket, token, state_dir, args.nft_bin)


if __name__ == "__main__":
    main()

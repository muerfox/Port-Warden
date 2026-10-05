#!/usr/bin/env python3
"""Low-interaction decoy. It never executes client input or opens outbound sockets."""

from __future__ import annotations

import json
import os
import socketserver
import sys
from datetime import datetime, timezone

BANNER = b"SSH-2.0-PortWarden-Decoy\r\n"
HTTP_BODY = b"This is a monitored decoy. No service is available here.\n"
MAX_SSH = 256
MAX_HTTP = 1024


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def client_host(address) -> str:
    if isinstance(address, tuple) and address:
        return str(address[0])
    return ""


def log_event(event: dict) -> None:
    if "dst_port" not in event:
        raw = os.environ.get("DECOY_PORT", "")
        if raw.isdigit():
            event["dst_port"] = int(raw)
    line = json.dumps(event, separators=(",", ":"))
    sys.stdout.write(line + "\n")
    sys.stdout.flush()
    path = os.environ.get("HONEYPOT_LOG", "")
    if not path:
        return
    try:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    except OSError:
        return


def printable(raw: bytes, limit: int) -> str:
    text = raw[:limit].decode("latin-1", "replace")
    cleaned = "".join(ch if 32 <= ord(ch) < 127 else "." for ch in text)
    return cleaned[:limit]


def summarize_http(raw: bytes) -> str:
    head = raw.split(b"\r\n", 1)[0][:300].decode("latin-1", "replace")
    parts = head.split(" ")
    method = parts[0][:16] if parts else ""
    path = parts[1][:180] if len(parts) > 1 else ""
    if "?" in path:
        path = path.split("?", 1)[0] + "?redacted"
    return f"{method} {path}".strip()


def handle_ssh(request, address) -> None:
    request.settimeout(3)
    try:
        request.sendall(BANNER)
        data = request.recv(MAX_SSH)
    except OSError:
        data = b""
    log_event(
        {
            "timestamp": utc_now(),
            "kind": "ssh",
            "src": client_host(address),
            "detail": printable(data, 80),
            "bytes": len(data),
        }
    )


def handle_http(request, address) -> None:
    request.settimeout(3)
    try:
        data = request.recv(MAX_HTTP)
    except OSError:
        data = b""
    body = HTTP_BODY
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"Connection: close\r\n"
        + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        + body
    )
    try:
        request.sendall(response)
    except OSError:
        pass
    log_event(
        {
            "timestamp": utc_now(),
            "kind": "http",
            "src": client_host(address),
            "detail": summarize_http(data),
            "bytes": len(data),
        }
    )


class DecoyHandler(socketserver.BaseRequestHandler):
    mode = "ssh"

    def handle(self) -> None:
        if self.mode == "http":
            handle_http(self.request, self.client_address)
        else:
            handle_ssh(self.request, self.client_address)


class DecoyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 16


def main() -> None:
    mode = os.environ.get("DECOY_MODE", "ssh")
    port = int(os.environ.get("DECOY_PORT", "2222" if mode == "ssh" else "8088"))
    if mode not in {"ssh", "http"}:
        raise SystemExit("DECOY_MODE must be ssh or http")
    DecoyHandler.mode = mode
    server = DecoyServer(("0.0.0.0", port), DecoyHandler)
    log_event({"timestamp": utc_now(), "kind": mode, "src": "", "detail": "decoy-listening", "bytes": 0})
    server.serve_forever()


if __name__ == "__main__":
    main()

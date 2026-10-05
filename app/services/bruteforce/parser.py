from __future__ import annotations

import ipaddress
import re

MAX_LINE = 2000

_PATTERNS = (
    ("failed_password", re.compile(r"Failed password for (?:invalid user )?\S+ from (?P<ip>\S+)")),
    ("invalid_user", re.compile(r"Invalid user \S+ from (?P<ip>\S+)")),
    ("failed_publickey", re.compile(r"Failed publickey for \S+ from (?P<ip>\S+)")),
    ("auth_failure", re.compile(r"authentication failure;.*\brhost=(?P<ip>[^\s]+)")),
)
_PORT = re.compile(r"\bport (?P<port>\d{1,5})\b")


def parse_auth_line(line: str) -> dict | None:
    """Return a failure reason and source IP, or None. Never executes log text."""
    if not line or len(line) > MAX_LINE or "\x00" in line:
        return None
    for reason, pattern in _PATTERNS:
        match = pattern.search(line)
        if not match:
            continue
        candidate = match.group("ip").strip().strip("\"'").rstrip(".,;")
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            return None
        result = {"src_ip": candidate, "reason": reason}
        port_match = _PORT.search(line)
        if port_match:
            port = int(port_match.group("port"))
            if 1 <= port <= 65535:
                result["dst_port"] = port
        return result
    return None

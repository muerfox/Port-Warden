from __future__ import annotations

import re

_SRC = re.compile(r"\bSRC=([0-9a-fA-F:.]+)")
_DPT = re.compile(r"\bDPT=(\d{1,5})")
_PROTO = re.compile(r"\bPROTO=([A-Za-z0-9]+)")


def parse_nft_drop(line: str) -> dict | None:
    """Parse a kernel/syslog line produced by nft log prefix pw:drop."""
    if "pw:drop" not in line:
        return None
    dpt = _DPT.search(line)
    if not dpt:
        return None
    port = int(dpt.group(1))
    if not 1 <= port <= 65535:
        return None
    src = _SRC.search(line)
    proto = _PROTO.search(line)
    protocol = (proto.group(1) if proto else "tcp").lower()
    if protocol.startswith("ipv6-"):
        protocol = protocol.split("-", 1)[-1]
    if protocol not in {"tcp", "udp", "sctp", "dccp"}:
        protocol = "tcp"
    return {
        "src_ip": src.group(1) if src else "",
        "dst_port": port,
        "protocol": protocol,
    }

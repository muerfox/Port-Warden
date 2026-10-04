from __future__ import annotations

# Templates only. Nothing here is inserted or applied unless an administrator saves it.
PRESETS: list[dict] = [
    {
        "id": "ssh",
        "name": "allow-ssh",
        "action": "allow",
        "direction": "in",
        "protocol": "tcp",
        "ports": "22",
        "comment": "SSH",
        "priority": 100,
    },
    {
        "id": "http",
        "name": "allow-http",
        "action": "allow",
        "direction": "in",
        "protocol": "tcp",
        "ports": "80",
        "comment": "HTTP",
        "priority": 100,
    },
    {
        "id": "https",
        "name": "allow-https",
        "action": "allow",
        "direction": "in",
        "protocol": "tcp",
        "ports": "443",
        "comment": "HTTPS",
        "priority": 100,
    },
    {
        "id": "dns-udp",
        "name": "allow-dns-udp",
        "action": "allow",
        "direction": "in",
        "protocol": "udp",
        "ports": "53",
        "comment": "DNS",
        "priority": 110,
    },
    {
        "id": "ntp",
        "name": "allow-ntp",
        "action": "allow",
        "direction": "in",
        "protocol": "udp",
        "ports": "123",
        "comment": "NTP",
        "priority": 120,
    },
]


def get_preset(preset_id: str) -> dict | None:
    for preset in PRESETS:
        if preset["id"] == preset_id:
            return dict(preset)
    return None

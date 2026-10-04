# Honeypots

Decoys are optional, labeled as monitoring-only, and off by default.

## What they are

`honeypots/decoy.py` is a short Python listener.

- SSH mode sends `SSH-2.0-PortWarden-Decoy` and closes after a small read. It does not start a shell.
- HTTP mode returns a static text response. Query strings are redacted before they are logged.
- It does not import subprocess and does not open outbound connections.
- Logs are a timestamp, source address, protocol, byte count, and a short printable preview.

The dashboard switch writes `data/honeypot/desired.json`. It does not talk to Docker. Start containers yourself:

```bash
docker compose --profile honeypots up -d
```

The compose profile puts the decoys on an internal network so they have no default route off the host. Published ports are 2222 and 8088, not 22 or 80. Containers drop all capabilities, run as uid 65534, use a read-only root filesystem, and are limited to 64 MB and 32 processes.

`data/honeypot` is created mode 1777 so that user can append JSON lines. Those files are decoy telemetry only.

## Operational and legal notes

- Run a decoy only on a host you administer, and only on addresses you intend to expose.
- Do not put a decoy on a port a real service needs.
- Source IP addresses are personal data in many places. Keep the retention window, and do not ship the logs to a third party without a reason.
- Do not use the telemetry to attack, scan, or retaliate against the remote host.
- A low-interaction banner can still attract abuse traffic and fill disk. Watch the log volume.
- The decoy is not a containment boundary for a kernel exploit in the network stack. It only avoids giving the caller a shell or a pivot through the decoy process.

from __future__ import annotations

import re

MAX_SCRIPT_BYTES = 256_000
_ALLOWED_FLUSH = "flush table inet port_warden"
_TABLE_LINES = {"table inet port_warden", "table inet port_warden {"}


def script_for_host(script: str, table_exists: bool) -> str:
    """Drop the bare table add. Flush only when the table is already loaded."""
    lines = []
    for line in script.splitlines():
        stripped = line.strip()
        if stripped == "table inet port_warden":
            continue
        if stripped == _ALLOWED_FLUSH and not table_exists:
            continue
        lines.append(line)
    prepared = "\n".join(lines).strip() + "\n"
    assert_safe_script(prepared)
    return prepared


def assert_safe_script(script: str) -> None:
    """Reject nft scripts that are not a single Port Warden table transaction."""
    if not isinstance(script, str) or not script.strip():
        raise ValueError("empty ruleset")
    if len(script.encode("utf-8")) > MAX_SCRIPT_BYTES:
        raise ValueError("ruleset too large")
    if "\x00" in script or "`" in script or "$(" in script:
        raise ValueError("invalid ruleset")
    if script.count("table inet port_warden") < 1:
        raise ValueError("ruleset must target table inet port_warden")
    if re.search(r"\binclude\b", script):
        raise ValueError("include is not allowed")
    for raw in script.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        lowered = line.lower()
        if lowered.startswith("flush ") and line != _ALLOWED_FLUSH:
            raise ValueError("only flushing inet port_warden is allowed")
        if lowered.startswith("delete "):
            raise ValueError("delete statements are not allowed in generated rulesets")
        if lowered.startswith("table ") and line not in _TABLE_LINES:
            raise ValueError("unexpected table in ruleset")
        if "ruleset" in lowered:
            raise ValueError("ruleset-wide nft statements are not allowed")

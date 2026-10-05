import os
import sys

import uvicorn

from app.config import load_settings


def ssl_kwargs(settings) -> dict[str, str]:
    cert = (settings.ssl_certfile or "").strip()
    key = (settings.ssl_keyfile or "").strip()
    if bool(cert) != bool(key):
        raise RuntimeError("ssl_certfile and ssl_keyfile must both be set, or both left empty")
    if not cert:
        return {}
    return {"ssl_certfile": cert, "ssl_keyfile": key}


def main() -> None:
    settings = load_settings(os.environ.get("PORT_WARDEN_CONFIG"))
    try:
        settings.assert_safe_bind()
        tls = ssl_kwargs(settings)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2) from exc
    uvicorn.run(
        "app.main:app",
        host=settings.bind_host,
        port=settings.bind_port,
        log_level="info",
        **tls,
    )


if __name__ == "__main__":
    main()

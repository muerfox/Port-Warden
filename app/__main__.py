import os
import sys

import uvicorn

from app.config import load_settings


def main() -> None:
    settings = load_settings(os.environ.get("PORT_WARDEN_CONFIG"))
    try:
        settings.assert_safe_bind()
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2) from exc
    uvicorn.run(
        "app.main:app",
        host=settings.bind_host,
        port=settings.bind_port,
        log_level="info",
    )


if __name__ == "__main__":
    main()

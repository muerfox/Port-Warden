from __future__ import annotations

import html
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.api.auth import router as auth_router
from app.api.firewall import router as firewall_router
from app.api.ops import router as ops_router
from app.config import Settings, load_settings
from app.db import build_session_factory
from app.logging_json import JsonLogger
from app.security import LoginLimiter
from app.services.bootstrap import bootstrap
from app.services.bruteforce.observe import observe_line
from app.services.bruteforce.tail import LogTailer
from app.services.bruteforce.tracker import FailureTracker
from app.services.events import purge_records
from app.services.firewall.backend import AgentBackend, DisabledBackend, LocalBackend, load_agent_token
from app.services.firewall.engine import FirewallEngine
from app.web.routes import router as web_router

STATIC_DIR = __import__("pathlib").Path(__file__).resolve().parent / "web" / "static"


def make_backend(settings: Settings):
    if settings.nft_backend == "local":
        return LocalBackend(settings.nft_bin)
    if settings.nft_backend == "agent":
        return AgentBackend(settings.agent_socket, load_agent_token(settings.agent_token_file))
    return DisabledBackend()


def create_app(settings: Settings | None = None, backend=None) -> FastAPI:
    settings = settings or load_settings(__import__("os").environ.get("PORT_WARDEN_CONFIG"))
    settings.assert_safe_bind()
    json_log = JsonLogger(settings.data_dir / "logs", settings.log_max_bytes, settings.log_retention_days)
    nft = backend if backend is not None else make_backend(settings)
    engine = FirewallEngine(settings, nft, json_log)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        db = app.state.session_factory()
        try:
            bootstrap(db, app.state.settings)
            purge_records(db, app.state.settings.log_retention_days)
            app.state.json_log.purge()
            app.state.engine.load_last_good(db)
            if (
                app.state.settings.restore_on_start
                and app.state.engine.enforces
                and app.state.engine.last_good
            ):
                try:
                    app.state.engine.backend.apply(app.state.engine.last_good)
                except Exception as exc:  # noqa: BLE001
                    app.state.json_log.emit(
                        "firewall_restore_failed",
                        action="failed",
                        src_ip="",
                        dst_port="",
                        rule_id="",
                        error=str(exc)[:300],
                    )
            db.commit()
        finally:
            db.close()
        tail = None
        log_path = app.state.settings.auth_log_path
        if log_path:
            from pathlib import Path

            def on_line(line: str) -> None:
                session = app.state.session_factory()
                try:
                    observe_line(
                        session,
                        app.state.tracker,
                        app.state.settings,
                        app.state.engine,
                        app.state.json_log,
                        line,
                    )
                    session.commit()
                except Exception:
                    session.rollback()
                    app.state.json_log.emit(
                        "log_parse_error",
                        action="skip",
                        src_ip="",
                        dst_port="",
                        rule_id="",
                    )
                finally:
                    session.close()

            tail = LogTailer(Path(log_path), on_line)
            tail.start()
        app.state.tail = tail
        yield
        if tail is not None:
            tail.stop()

    app = FastAPI(title="Port Warden", version="0.1.0", docs_url=None, redoc_url=None, lifespan=lifespan)
    app.state.settings = settings
    app.state.session_factory = build_session_factory(settings)
    app.state.json_log = json_log
    app.state.engine = engine
    app.state.tracker = FailureTracker()
    app.state.limiter = LoginLimiter(settings.login_rate_limit, settings.login_rate_window)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException):
        detail = exc.detail if isinstance(exc.detail, str) else "Request failed"
        if request.url.path.startswith("/api/"):
            return JSONResponse({"detail": detail}, status_code=exc.status_code)
        if exc.status_code == 401:
            return RedirectResponse("/login", status_code=303)
        safe = html.escape(detail)
        return HTMLResponse(
            f"<!DOCTYPE html><title>Port Warden</title><p>{safe}</p><p><a href='/'>Back</a></p>",
            status_code=exc.status_code,
        )

    @app.get("/health")
    def health():
        return {"status": "ok"}

    app.include_router(auth_router, prefix="/api/v1")
    app.include_router(firewall_router, prefix="/api/v1")
    app.include_router(ops_router, prefix="/api/v1")
    app.include_router(web_router)
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return app

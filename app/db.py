from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import Settings


class Base(DeclarativeBase):
    pass


def make_engine(url: str):
    connect_args = {}
    engine_kwargs = {}
    if url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
        if url.endswith(":memory:") or url.endswith(":memory:?cache=shared"):
            engine_kwargs["poolclass"] = StaticPool
    return create_engine(url, connect_args=connect_args, **engine_kwargs)


def ensure_sqlite_parent(url: str) -> None:
    prefix = "sqlite:///"
    if not url.startswith(prefix):
        return
    path = url[len(prefix) :]
    if path in {":memory:", ""} or path.startswith(":memory:"):
        return
    Path(path).parent.mkdir(parents=True, exist_ok=True)


def build_session_factory(settings: Settings):
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    (settings.data_dir / "logs").mkdir(parents=True, exist_ok=True)
    (settings.data_dir / "snapshots").mkdir(parents=True, exist_ok=True)
    (settings.data_dir / "honeypot").mkdir(parents=True, exist_ok=True)
    ensure_sqlite_parent(settings.database_url)
    # Register models on Base.metadata before create_all.
    import app.models  # noqa: F401

    engine = make_engine(settings.database_url)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)

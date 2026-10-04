from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings
from app.models import IpList, User
from app.security import hash_password
from app.services.firewall.engine import get_setting, set_setting
from app.services.firewall.validate import validate_name
from app.services.honeypot_store import ensure_honeypots
from app.timeutil import utcnow


def bootstrap(db: Session, settings: Settings) -> None:
    if db.scalar(select(User).limit(1)) is None and settings.admin_password:
        if len(settings.admin_password) < 12:
            raise RuntimeError("PORT_WARDEN_ADMIN_PASSWORD must be at least 12 characters")
        username = validate_name(settings.admin_username)
        db.add(
            User(
                username=username,
                password_hash=hash_password(settings.admin_password),
                totp_secret=None,
                totp_enabled=False,
                created_at=utcnow(),
            )
        )
    for name, kind in (("allowlist", "allow"), ("denylist", "deny")):
        if db.scalar(select(IpList).where(IpList.name == name)) is None:
            db.add(IpList(name=name, kind=kind, comment="Built-in", builtin=True))
    ensure_honeypots(db)
    if get_setting(db, "firewall_mode") is None:
        set_setting(db, "firewall_mode", settings.firewall_mode)
    db.commit()

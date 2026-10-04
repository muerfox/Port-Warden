from __future__ import annotations

import hmac
import ipaddress

from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

from app.models import SessionRow
from app.security import hash_token
from app.services.firewall.backend import NftError
from app.services.firewall.engine import LockoutError
from app.timeutil import utcnow

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def client_ip(request: Request) -> str:
    if request.client is None:
        return ""
    host = request.client.host or ""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return ""
    return host


def db_session(request: Request):
    db: Session = request.app.state.session_factory()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def load_session(db: Session, raw_token: str | None) -> SessionRow | None:
    if not raw_token:
        return None
    row = db.get(SessionRow, hash_token(raw_token))
    if row is None:
        return None
    if row.expires_at <= utcnow():
        db.delete(row)
        return None
    return row


def require_user(request: Request, db: Session) -> SessionRow:
    row = load_session(db, request.cookies.get("pw_session"))
    if row is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    if request.method not in SAFE_METHODS:
        supplied = request.headers.get("x-csrf-token", "")
        if not supplied or not hmac.compare_digest(supplied, row.csrf_token):
            raise HTTPException(status_code=403, detail="CSRF validation failed")
    return row


def api_error(fn):
    try:
        return fn()
    except LockoutError as exc:
        raise HTTPException(status_code=409, detail=exc.message) from exc
    except NftError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

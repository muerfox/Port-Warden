from __future__ import annotations

import pyotp
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import client_ip, db_session, require_user
from app.models import SessionRow, User
from app.schemas import LoginIn, PasswordIn, TotpConfirm
from app.security import hash_password, new_token, session_expiry, verify_dummy, verify_password
from app.services.events import record_audit, record_event
from app.services.firewall.validate import validate_name
from app.timeutil import utcnow

router = APIRouter(prefix="/auth", tags=["auth"])


class MfaRequired(Exception):
    pass


def authenticate(request: Request, db: Session, username: str, password: str, totp: str | None) -> User:
    ip = client_ip(request) or "unknown"
    limiter = request.app.state.limiter
    limiter.check(ip)
    try:
        name = validate_name(username)
    except ValueError:
        verify_dummy(password)
        limiter.fail(ip)
        raise HTTPException(status_code=401, detail="Invalid credentials") from None
    user = db.scalar(select(User).where(User.username == name))
    ui_port = int(request.app.state.settings.bind_port)

    def _deny() -> None:
        record_event(
            db,
            request.app.state.json_log,
            "login_failure",
            src_ip=ip,
            dst_port=ui_port,
            action="denied",
        )
        # Persist before HTTPException rolls the request session back.
        db.commit()

    if user is None:
        verify_dummy(password)
        limiter.fail(ip)
        _deny()
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_password(user.password_hash, password):
        limiter.fail(ip)
        _deny()
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if user.totp_enabled:
        if not totp:
            raise MfaRequired()
        if not user.totp_secret or not pyotp.TOTP(user.totp_secret).verify(totp, valid_window=1):
            limiter.fail(ip)
            _deny()
            raise HTTPException(status_code=401, detail="Invalid credentials")
    limiter.clear(ip)
    return user


def start_session(request: Request, db: Session, user: User, response: Response) -> dict:
    from app.security import hash_token

    raw = new_token()
    row = SessionRow(
        token_hash=hash_token(raw),
        user_id=user.id,
        csrf_token=new_token(24),
        expires_at=session_expiry(request.app.state.settings.session_hours),
        created_at=utcnow(),
        ip=client_ip(request),
        user=user,
    )
    db.add(row)
    db.flush()
    settings = request.app.state.settings
    response.set_cookie(
        "pw_session",
        raw,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        max_age=settings.session_hours * 3600,
        path="/",
    )
    record_audit(
        db,
        request.app.state.json_log,
        actor=user.username,
        action="login",
        target="session",
        src_ip=client_ip(request),
    )
    return {"username": user.username, "csrf_token": row.csrf_token, "mfa_enabled": user.totp_enabled}


@router.post("/login")
def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(db_session)):
    if db.scalar(select(User).limit(1)) is None:
        raise HTTPException(status_code=503, detail="No administrator is configured")
    try:
        user = authenticate(request, db, body.username, body.password, body.totp)
    except MfaRequired:
        return {"mfa_required": True}
    return start_session(request, db, user, response)


@router.post("/logout")
def logout(request: Request, response: Response, db: Session = Depends(db_session)):
    session = require_user(request, db)
    db.delete(session)
    record_audit(
        db,
        request.app.state.json_log,
        actor=session.user.username,
        action="logout",
        target="session",
        src_ip=client_ip(request),
    )
    response.delete_cookie("pw_session", path="/")
    return {"ok": True}


@router.get("/me")
def me(request: Request, db: Session = Depends(db_session)):
    session = require_user(request, db)
    return {
        "username": session.user.username,
        "mfa_enabled": session.user.totp_enabled,
        "csrf_token": session.csrf_token,
    }


@router.post("/mfa/setup")
def mfa_setup(request: Request, db: Session = Depends(db_session)):
    session = require_user(request, db)
    user = session.user
    if user.totp_enabled:
        raise HTTPException(status_code=400, detail="MFA is already enabled")
    secret = pyotp.random_base32()
    user.totp_secret = secret
    uri = pyotp.TOTP(secret).provisioning_uri(name=user.username, issuer_name="Port Warden")
    record_audit(
        db,
        request.app.state.json_log,
        actor=user.username,
        action="mfa_setup",
        target=user.username,
        src_ip=client_ip(request),
    )
    return {"secret": secret, "otpauth_uri": uri}


@router.post("/mfa/enable")
def mfa_enable(body: TotpConfirm, request: Request, db: Session = Depends(db_session)):
    session = require_user(request, db)
    user = session.user
    if not user.totp_secret:
        raise HTTPException(status_code=400, detail="Set up MFA before enabling it")
    if not pyotp.TOTP(user.totp_secret).verify(body.code, valid_window=1):
        raise HTTPException(status_code=400, detail="Invalid authentication code")
    user.totp_enabled = True
    record_audit(
        db,
        request.app.state.json_log,
        actor=user.username,
        action="mfa_enable",
        target=user.username,
        src_ip=client_ip(request),
    )
    return {"mfa_enabled": True}


@router.post("/mfa/disable")
def mfa_disable(body: PasswordIn, request: Request, db: Session = Depends(db_session)):
    session = require_user(request, db)
    user = session.user
    if not verify_password(user.password_hash, body.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if user.totp_enabled:
        if not body.totp or not user.totp_secret or not pyotp.TOTP(user.totp_secret).verify(body.totp, valid_window=1):
            raise HTTPException(status_code=401, detail="Invalid credentials")
    user.totp_enabled = False
    user.totp_secret = None
    record_audit(
        db,
        request.app.state.json_log,
        actor=user.username,
        action="mfa_disable",
        target=user.username,
        src_ip=client_ip(request),
    )
    return {"mfa_enabled": False}


def change_password(db: Session, user: User, new_password: str) -> None:
    if len(new_password) < 12:
        raise ValueError("password must be at least 12 characters")
    user.password_hash = hash_password(new_password)

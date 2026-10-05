from __future__ import annotations

import hmac
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.auth import MfaRequired, authenticate, start_session
from app.api.deps import client_ip, db_session, load_session
from app.models import AuditLog, Ban, Event, Honeypot, IpList, IpListEntry, Rule
from app.serialize import ban_dict, honeypot_dict, list_dict, rule_dict
from app.services.events import audit_dict, event_dict, record_audit
from app.services.firewall.presets import PRESETS, get_preset
from app.services.firewall.protections import (
    disable_protection,
    enable_protection,
    enable_recommended,
    list_protection_status,
)
from app.services.honeypot_store import read_telemetry, write_desired
from app.services.analytics.ports import port_attack_stats
from app.services.inventory.ports import REACHABILITY_NOTE, inventory_warning, read_host_listeners
from app.services.inventory.workspace import (
    close_port,
    effective_open_ports,
    effective_ssh_port,
    keep_port_open,
    panel_rows,
)
from app.services.records import add_entry, bf_config, create_ban, create_rule, lift_ban, save_bf_config_fields
from app.services.firewall.backend import NftError
from app.services.firewall.engine import LockoutError, set_setting
from app.timeutil import parse_form_datetime

router = APIRouter(tags=["web"])
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent / "templates"))


_TITLES = {
    "status.html": "Status",
    "ports.html": "Ports",
    "traffic.html": "Traffic",
    "protections.html": "Protections",
    "rules.html": "Rules",
    "lists.html": "Allow and deny lists",
    "bans.html": "Bans",
    "events.html": "Events",
    "audit.html": "Audit",
    "honeypots.html": "Honeypots",
    "firewall.html": "Firewall",
}


def _page(request: Request, name: str, session, status: int = 200, **extra):
    context = {
        "title": extra.pop("title", _TITLES.get(name, "Port Warden")),
        "csrf_token": session.csrf_token if session else "",
        "username": session.user.username if session else "",
        "message": request.query_params.get("msg", ""),
        **extra,
    }
    return templates.TemplateResponse(request, name, context, status_code=status)


def _redirect(path: str, message: str) -> RedirectResponse:
    return RedirectResponse(f"{path}?msg={quote(message)}", status_code=303)


def _session_or_401(request: Request, db: Session):
    row = load_session(db, request.cookies.get("pw_session"))
    if row is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    return row


def _csrf(request: Request, session, form_token: str) -> None:
    supplied = request.headers.get("x-csrf-token") or form_token
    if not supplied or not hmac.compare_digest(supplied, session.csrf_token):
        raise HTTPException(status_code=403, detail="CSRF validation failed")


@router.get("/login")
def login_page(request: Request, db: Session = Depends(db_session)):
    if load_session(db, request.cookies.get("pw_session")):
        return RedirectResponse("/", status_code=303)
    return _page(request, "login.html", None, error="")


@router.post("/login")
def login_submit(
    request: Request,
    db: Session = Depends(db_session),
    username: str = Form(...),
    password: str = Form(...),
    totp: str = Form(""),
):
    try:
        user = authenticate(request, db, username, password, totp or None)
    except MfaRequired:
        return _page(request, "login.html", None, status=401, error="Authentication code required.")
    except HTTPException as exc:
        if exc.status_code != 401:
            raise
        return _page(request, "login.html", None, status=401, error="Invalid credentials.")
    response = _redirect("/", "Signed in.")
    start_session(request, db, user, response)
    return response


@router.post("/logout")
def logout(request: Request, db: Session = Depends(db_session), csrf_token: str = Form("")):
    session = _session_or_401(request, db)
    _csrf(request, session, csrf_token)
    record_audit(
        db,
        request.app.state.json_log,
        actor=session.user.username,
        action="logout",
        target="session",
        src_ip=client_ip(request),
    )
    db.delete(session)
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie("pw_session", path="/")
    return response


@router.get("/")
def home(request: Request, db: Session = Depends(db_session)):
    session = _session_or_401(request, db)
    firewall = request.app.state.engine.status(db)
    listeners = read_host_listeners()
    active = db.scalars(select(Ban).where(Ban.lifted_at.is_(None))).all()
    traffic = port_attack_stats(db, request.app.state.settings, hours=24, limit=5)
    return _page(
        request,
        "status.html",
        session,
        firewall=firewall,
        listener_count=len(listeners),
        ban_count=len(list(active)),
        bruteforce=bf_config(db, request.app.state.settings),
        note=REACHABILITY_NOTE,
        traffic=traffic,
    )


@router.get("/traffic")
def traffic_page(request: Request, db: Session = Depends(db_session), hours: int = 24):
    session = _session_or_401(request, db)
    if hours not in {24, 72, 168}:
        hours = 24
    stats = port_attack_stats(db, request.app.state.settings, hours=hours, limit=12)
    return _page(
        request,
        "traffic.html",
        session,
        stats=stats,
        hours=hours,
    )


@router.get("/ports")
def ports(request: Request, db: Session = Depends(db_session)):
    session = _session_or_401(request, db)
    settings = request.app.state.settings
    return _page(
        request,
        "ports.html",
        session,
        listeners=panel_rows(db, settings),
        note=REACHABILITY_NOTE,
        warning=inventory_warning(
            host_network=settings.host_network,
            nft_backend=settings.nft_backend,
            host_pid=settings.host_pid,
        ),
        targets=settings.reachability_targets,
        ssh_port=effective_ssh_port(db, settings),
        open_ports=effective_open_ports(db, settings),
    )


@router.post("/ports/keep-open")
def ports_keep_open(
    request: Request,
    db: Session = Depends(db_session),
    csrf_token: str = Form(""),
    port: int = Form(...),
):
    session = _session_or_401(request, db)
    _csrf(request, session, csrf_token)
    try:
        keep_port_open(db, request.app.state.settings, port)
    except ValueError as exc:
        return _redirect("/ports", str(exc))
    record_audit(
        db,
        request.app.state.json_log,
        actor=session.user.username,
        action="port_keep_open",
        target=str(port),
        src_ip=client_ip(request),
    )
    return _redirect("/ports", f"Port {port} will stay open after Apply.")


@router.post("/ports/close")
def ports_close(
    request: Request,
    db: Session = Depends(db_session),
    csrf_token: str = Form(""),
    port: int = Form(...),
):
    session = _session_or_401(request, db)
    _csrf(request, session, csrf_token)
    try:
        close_port(db, request.app.state.settings, port)
    except ValueError as exc:
        return _redirect("/ports", str(exc))
    record_audit(
        db,
        request.app.state.json_log,
        actor=session.user.username,
        action="port_close",
        target=str(port),
        src_ip=client_ip(request),
    )
    return _redirect("/ports", f"Port {port} will drop in enforce after Apply.")


@router.get("/protections")
def protections_page(request: Request, db: Session = Depends(db_session)):
    session = _session_or_401(request, db)
    return _page(
        request,
        "protections.html",
        session,
        packs=list_protection_status(db),
    )


@router.post("/protections/enable-recommended")
def protections_enable_recommended(
    request: Request,
    db: Session = Depends(db_session),
    csrf_token: str = Form(""),
):
    session = _session_or_401(request, db)
    _csrf(request, session, csrf_token)
    enable_recommended(db)
    record_audit(
        db,
        request.app.state.json_log,
        actor=session.user.username,
        action="protections_enable_recommended",
        target="recommended",
        src_ip=client_ip(request),
    )
    return _redirect("/protections", "Recommended protections enabled in desired rules. Preview/Apply on Firewall.")


@router.post("/protections/{pack_id}/enable")
def protections_enable(
    pack_id: str,
    request: Request,
    db: Session = Depends(db_session),
    csrf_token: str = Form(""),
):
    session = _session_or_401(request, db)
    _csrf(request, session, csrf_token)
    try:
        enable_protection(db, pack_id)
    except ValueError as exc:
        return _redirect("/protections", str(exc))
    record_audit(
        db,
        request.app.state.json_log,
        actor=session.user.username,
        action="protection_enable",
        target=pack_id,
        src_ip=client_ip(request),
    )
    return _redirect("/protections", f"Protection '{pack_id}' enabled in desired rules. Preview/Apply on Firewall.")


@router.post("/protections/{pack_id}/disable")
def protections_disable(
    pack_id: str,
    request: Request,
    db: Session = Depends(db_session),
    csrf_token: str = Form(""),
):
    session = _session_or_401(request, db)
    _csrf(request, session, csrf_token)
    try:
        disable_protection(db, pack_id)
    except ValueError as exc:
        return _redirect("/protections", str(exc))
    record_audit(
        db,
        request.app.state.json_log,
        actor=session.user.username,
        action="protection_disable",
        target=pack_id,
        src_ip=client_ip(request),
    )
    return _redirect("/protections", f"Protection '{pack_id}' removed from desired rules. Preview/Apply on Firewall.")


@router.get("/rules")
def rules_page(request: Request, db: Session = Depends(db_session)):
    session = _session_or_401(request, db)
    preset = get_preset(request.query_params.get("preset", "")) or {}
    rows = db.scalars(select(Rule).order_by(Rule.priority, Rule.name)).all()
    return _page(
        request,
        "rules.html",
        session,
        rules=[rule_dict(row) for row in rows],
        presets=PRESETS,
        draft=preset,
        error="",
    )


@router.post("/rules")
def rules_create(
    request: Request,
    db: Session = Depends(db_session),
    csrf_token: str = Form(""),
    name: str = Form(...),
    action: str = Form(...),
    direction: str = Form(...),
    protocol: str = Form(...),
    src_cidr: str = Form(""),
    dst_cidr: str = Form(""),
    ports: str = Form(""),
    comment: str = Form(""),
    priority: int = Form(100),
    expires_at: str = Form(""),
):
    session = _session_or_401(request, db)
    _csrf(request, session, csrf_token)
    try:
        row = create_rule(
            db,
            {
                "name": name,
                "action": action,
                "direction": direction,
                "protocol": protocol,
                "src_cidr": src_cidr,
                "dst_cidr": dst_cidr,
                "ports": ports,
                "comment": comment,
                "priority": priority,
                "enabled": True,
                "expires_at": parse_form_datetime(expires_at),
            },
        )
    except (ValueError, TypeError) as exc:
        rows = db.scalars(select(Rule).order_by(Rule.priority, Rule.name)).all()
        return _page(
            request,
            "rules.html",
            session,
            status=400,
            rules=[rule_dict(item) for item in rows],
            presets=PRESETS,
            draft={},
            error=str(exc),
        )
    record_audit(
        db,
        request.app.state.json_log,
        actor=session.user.username,
        action="rule_create",
        target=row.name,
        src_ip=client_ip(request),
    )
    return _redirect("/rules", "Rule saved. It is not installed until you preview and apply.")


@router.post("/rules/{rule_id}/delete")
def rules_delete(rule_id: int, request: Request, db: Session = Depends(db_session), csrf_token: str = Form("")):
    session = _session_or_401(request, db)
    _csrf(request, session, csrf_token)
    row = db.get(Rule, rule_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    name = row.name
    db.delete(row)
    record_audit(
        db,
        request.app.state.json_log,
        actor=session.user.username,
        action="rule_delete",
        target=name,
        src_ip=client_ip(request),
    )
    if request.headers.get("hx-request"):
        return HTMLResponse("<tr><td colspan='7'>Rule removed from desired state.</td></tr>")
    return _redirect("/rules", "Rule removed from desired state.")


@router.get("/lists")
def lists_page(request: Request, db: Session = Depends(db_session)):
    session = _session_or_401(request, db)
    rows = db.scalars(select(IpList).order_by(IpList.name)).all()
    payload = []
    for row in rows:
        entries = list(db.scalars(select(IpListEntry).where(IpListEntry.list_id == row.id)))
        payload.append(list_dict(row, entries))
    return _page(request, "lists.html", session, lists=payload, error="")


@router.post("/lists/{list_id}/entries")
def lists_add(
    list_id: int,
    request: Request,
    db: Session = Depends(db_session),
    csrf_token: str = Form(""),
    cidr: str = Form(...),
    comment: str = Form(""),
):
    session = _session_or_401(request, db)
    _csrf(request, session, csrf_token)
    ip_list = db.get(IpList, list_id)
    if ip_list is None:
        raise HTTPException(status_code=404, detail="List not found")
    try:
        row = add_entry(db, ip_list, cidr, comment, None, request.app.state.settings)
    except ValueError as exc:
        return _redirect("/lists", str(exc))
    record_audit(
        db,
        request.app.state.json_log,
        actor=session.user.username,
        action="list_entry_add",
        target=f"{ip_list.name}:{row.cidr}",
        src_ip=client_ip(request),
    )
    return _redirect("/lists", "Entry saved. Apply the firewall to enforce it.")


@router.get("/bans")
def bans_page(request: Request, db: Session = Depends(db_session)):
    session = _session_or_401(request, db)
    rows = db.scalars(select(Ban).order_by(Ban.id.desc())).all()
    return _page(
        request,
        "bans.html",
        session,
        bans=[ban_dict(row) for row in rows],
        settings=bf_config(db, request.app.state.settings),
        error="",
    )


@router.post("/bans")
def bans_create(
    request: Request,
    db: Session = Depends(db_session),
    csrf_token: str = Form(""),
    ip: str = Form(...),
    reason: str = Form("manual"),
    permanent: str = Form(""),
    seconds: int = Form(3600),
):
    session = _session_or_401(request, db)
    _csrf(request, session, csrf_token)
    try:
        row = create_ban(
            db,
            request.app.state.settings,
            request.app.state.engine,
            ip=ip,
            reason=reason,
            source="manual",
            permanent=permanent == "yes",
            seconds=seconds,
        )
    except (ValueError, NftError) as exc:
        return _redirect("/bans", str(exc))
    record_audit(
        db,
        request.app.state.json_log,
        actor=session.user.username,
        action="ban_create",
        target=row.ip,
        src_ip=client_ip(request),
    )
    return _redirect("/bans", "Ban recorded.")


@router.post("/bans/{ban_id}/unban")
def bans_unban(ban_id: int, request: Request, db: Session = Depends(db_session), csrf_token: str = Form("")):
    session = _session_or_401(request, db)
    _csrf(request, session, csrf_token)
    row = db.get(Ban, ban_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Ban not found")
    try:
        lift_ban(db, request.app.state.engine, row)
    except (ValueError, NftError) as exc:
        if request.headers.get("hx-request"):
            return HTMLResponse(f"<p>{exc}</p>", status_code=400)
        return _redirect("/bans", str(exc))
    record_audit(
        db,
        request.app.state.json_log,
        actor=session.user.username,
        action="unban",
        target=row.ip,
        src_ip=client_ip(request),
    )
    if request.headers.get("hx-request"):
        return HTMLResponse("<p>Ban lifted.</p>")
    return _redirect("/bans", "Ban lifted.")


@router.post("/bruteforce/settings")
def bf_save(
    request: Request,
    db: Session = Depends(db_session),
    csrf_token: str = Form(""),
    threshold: int = Form(...),
    window_seconds: int = Form(...),
    ban_seconds: int = Form(...),
    cooldown_seconds: int = Form(...),
    permanent_after: int = Form(...),
):
    session = _session_or_401(request, db)
    _csrf(request, session, csrf_token)
    payload = {
        "threshold": threshold,
        "window_seconds": window_seconds,
        "ban_seconds": ban_seconds,
        "cooldown_seconds": cooldown_seconds,
        "permanent_after": permanent_after,
    }
    try:
        if not 1 <= threshold <= 100 or not 10 <= window_seconds <= 86400:
            raise ValueError("threshold or window is out of range")
        if not 60 <= ban_seconds <= 31_536_000 or not 0 <= cooldown_seconds <= 86400:
            raise ValueError("ban duration or cooldown is out of range")
        if not 0 <= permanent_after <= 100:
            raise ValueError("permanent_after is out of range")
        save_bf_config_fields(db, payload)
    except ValueError as exc:
        return _redirect("/bans", str(exc))
    record_audit(
        db,
        request.app.state.json_log,
        actor=session.user.username,
        action="bruteforce_settings",
        target="thresholds",
        src_ip=client_ip(request),
    )
    return _redirect("/bans", "Brute-force settings saved.")


@router.get("/events")
def events_page(request: Request, db: Session = Depends(db_session)):
    session = _session_or_401(request, db)
    rows = db.scalars(select(Event).order_by(Event.id.desc()).limit(200)).all()
    return _page(
        request,
        "events.html",
        session,
        events=[event_dict(row) for row in rows],
        retention=request.app.state.settings.log_retention_days,
    )


@router.get("/audit")
def audit_page(request: Request, db: Session = Depends(db_session)):
    session = _session_or_401(request, db)
    rows = db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(200)).all()
    return _page(
        request,
        "audit.html",
        session,
        rows=[audit_dict(row) for row in rows],
        retention=request.app.state.settings.log_retention_days,
    )


@router.get("/honeypots")
def honeypots_page(request: Request, db: Session = Depends(db_session)):
    session = _session_or_401(request, db)
    rows = db.scalars(select(Honeypot).order_by(Honeypot.name)).all()
    directory = request.app.state.settings.data_dir / "honeypot"
    return _page(
        request,
        "honeypots.html",
        session,
        honeypots=[honeypot_dict(row) for row in rows],
        telemetry=read_telemetry(directory),
    )


@router.post("/honeypots/{name}/toggle")
def honeypots_toggle(
    name: str,
    request: Request,
    db: Session = Depends(db_session),
    csrf_token: str = Form(""),
    enabled: str = Form("no"),
):
    session = _session_or_401(request, db)
    _csrf(request, session, csrf_token)
    row = db.scalar(select(Honeypot).where(Honeypot.name == name))
    if row is None:
        raise HTTPException(status_code=404, detail="Honeypot not found")
    row.enabled = enabled == "yes"
    write_desired(db, request.app.state.settings.data_dir / "honeypot")
    record_audit(
        db,
        request.app.state.json_log,
        actor=session.user.username,
        action="honeypot_enable" if row.enabled else "honeypot_disable",
        target=row.name,
        src_ip=client_ip(request),
    )
    return _redirect("/honeypots", "Decoy desired state saved. Containers are not started from this page.")


@router.get("/firewall")
def firewall_page(request: Request, db: Session = Depends(db_session)):
    session = _session_or_401(request, db)
    return _page(
        request,
        "firewall.html",
        session,
        status_info=request.app.state.engine.status(db),
        preview=None,
        error="",
        management=request.app.state.settings.management_cidrs,
        ssh_port=effective_ssh_port(db, request.app.state.settings),
        open_ports=effective_open_ports(db, request.app.state.settings),
    )


@router.post("/firewall/preview")
def firewall_preview(request: Request, db: Session = Depends(db_session), csrf_token: str = Form("")):
    session = _session_or_401(request, db)
    _csrf(request, session, csrf_token)
    preview = request.app.state.engine.preview(db, client_ip(request))
    record_audit(
        db,
        request.app.state.json_log,
        actor=session.user.username,
        action="firewall_preview",
        target=preview.sha256[:12],
        src_ip=client_ip(request),
    )
    return _page(
        request,
        "firewall.html",
        session,
        status_info=request.app.state.engine.status(db),
        preview=preview,
        error="",
        management=request.app.state.settings.management_cidrs,
        ssh_port=effective_ssh_port(db, request.app.state.settings),
        open_ports=effective_open_ports(db, request.app.state.settings),
    )


@router.post("/firewall/apply")
def firewall_apply(
    request: Request,
    db: Session = Depends(db_session),
    csrf_token: str = Form(""),
    confirm_token: str = Form(...),
    lockout_phrase: str = Form(""),
):
    session = _session_or_401(request, db)
    _csrf(request, session, csrf_token)
    try:
        result = request.app.state.engine.apply(db, confirm_token, client_ip(request), lockout_phrase)
    except (LockoutError, ValueError, NftError) as exc:
        text = exc.message if isinstance(exc, LockoutError) else str(exc)
        return _redirect("/firewall", text)
    record_audit(
        db,
        request.app.state.json_log,
        actor=session.user.username,
        action="firewall_apply",
        target=result["status"],
        src_ip=client_ip(request),
    )
    if result["applied"]:
        return _redirect("/firewall", "Ruleset applied to the host nftables table.")
    return _redirect("/firewall", "Ruleset staged. The host firewall was not changed.")


@router.post("/firewall/rollback")
def firewall_rollback(request: Request, db: Session = Depends(db_session), csrf_token: str = Form("")):
    session = _session_or_401(request, db)
    _csrf(request, session, csrf_token)
    try:
        request.app.state.engine.rollback(db, client_ip(request))
    except (ValueError, NftError) as exc:
        return _redirect("/firewall", str(exc))
    record_audit(
        db,
        request.app.state.json_log,
        actor=session.user.username,
        action="firewall_rollback",
        target="previous",
        src_ip=client_ip(request),
    )
    return _redirect("/firewall", "Rolled back to the previous applied snapshot.")


@router.post("/firewall/mode")
def firewall_mode(
    request: Request,
    db: Session = Depends(db_session),
    csrf_token: str = Form(""),
    mode: str = Form(...),
    monitor_ack: str = Form(""),
):
    session = _session_or_401(request, db)
    _csrf(request, session, csrf_token)
    if mode not in {"enforce", "monitor"}:
        return _redirect("/firewall", "Unknown mode.")
    if mode == "monitor" and monitor_ack != "yes":
        return _redirect("/firewall", "Monitor mode needs an explicit acknowledgement. Nothing was changed.")
    set_setting(db, "firewall_mode", mode)
    record_audit(
        db,
        request.app.state.json_log,
        actor=session.user.username,
        action="firewall_mode",
        target=mode,
        src_ip=client_ip(request),
    )
    return _redirect("/firewall", "Mode stored. Preview and apply before it is enforced.")

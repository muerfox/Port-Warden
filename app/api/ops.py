from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import api_error, client_ip, db_session, require_user
from app.models import AuditLog, Ban, Event, Honeypot
from app.schemas import BanIn, BfSettingsIn, IngestIn, ReachabilityIn
from app.serialize import ban_dict, honeypot_dict
from app.services.bruteforce.observe import observe_line
from app.services.events import audit_dict as _audit_dict
from app.services.events import event_dict, record_audit, record_event
from app.services.honeypot_store import read_telemetry, write_desired
from app.services.inventory.ports import (
    REACHABILITY_NOTE,
    check_reachability,
    inventory_warning,
    read_host_listeners,
)
from app.services.records import bf_config, create_ban, lift_ban, save_bf_config_fields

router = APIRouter(tags=["ops"])


@router.get("/status")
def status(request: Request, db: Session = Depends(db_session)):
    require_user(request, db)
    firewall = request.app.state.engine.status(db)
    listeners = read_host_listeners()
    bans = db.scalars(select(Ban).where(Ban.lifted_at.is_(None))).all()
    return {
        "firewall": firewall,
        "active_bans": len(list(bans)),
        "listeners": len(listeners),
        "bruteforce": bf_config(db, request.app.state.settings),
        "reachability_note": REACHABILITY_NOTE,
    }


@router.get("/bans")
def get_bans(request: Request, db: Session = Depends(db_session)):
    require_user(request, db)
    rows = db.scalars(select(Ban).order_by(Ban.id.desc())).all()
    return {"bans": [ban_dict(row) for row in rows], "settings": bf_config(db, request.app.state.settings)}


@router.post("/bans")
def post_ban(body: BanIn, request: Request, db: Session = Depends(db_session)):
    session = require_user(request, db)

    def act():
        row = create_ban(
            db,
            request.app.state.settings,
            request.app.state.engine,
            ip=body.ip,
            reason=body.reason,
            source="manual",
            permanent=body.permanent,
            seconds=body.seconds,
        )
        record_audit(
            db,
            request.app.state.json_log,
            actor=session.user.username,
            action="ban_create",
            target=row.ip,
            src_ip=client_ip(request),
        )
        record_event(
            db,
            request.app.state.json_log,
            "ban",
            src_ip=row.ip,
            action="ban",
            rule_id=str(row.id),
            details={"source": "manual", "permanent": row.permanent},
        )
        return ban_dict(row)

    return api_error(act)


@router.post("/bans/{ban_id}/unban")
def unban(ban_id: int, request: Request, db: Session = Depends(db_session)):
    session = require_user(request, db)
    row = db.get(Ban, ban_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Ban not found")

    def act():
        lift_ban(db, request.app.state.engine, row)
        record_audit(
            db,
            request.app.state.json_log,
            actor=session.user.username,
            action="unban",
            target=row.ip,
            src_ip=client_ip(request),
        )
        record_event(
            db,
            request.app.state.json_log,
            "unban",
            src_ip=row.ip,
            action="unban",
            rule_id=str(row.id),
        )
        return ban_dict(row)

    return api_error(act)


@router.get("/bruteforce/settings")
def get_bf(request: Request, db: Session = Depends(db_session)):
    require_user(request, db)
    return bf_config(db, request.app.state.settings)


@router.put("/bruteforce/settings")
def put_bf(body: BfSettingsIn, request: Request, db: Session = Depends(db_session)):
    session = require_user(request, db)
    save_bf_config_fields(db, body.model_dump())
    record_audit(
        db,
        request.app.state.json_log,
        actor=session.user.username,
        action="bruteforce_settings",
        target="thresholds",
        src_ip=client_ip(request),
    )
    return bf_config(db, request.app.state.settings)


@router.post("/bruteforce/ingest")
def ingest(body: IngestIn, request: Request, db: Session = Depends(db_session)):
    session = require_user(request, db)
    if len(body.lines) > 500:
        raise HTTPException(status_code=400, detail="too many lines")
    results = []
    for line in body.lines:
        if len(line) > 2000:
            results.append(None)
            continue
        results.append(
            observe_line(
                db,
                request.app.state.tracker,
                request.app.state.settings,
                request.app.state.engine,
                request.app.state.json_log,
                line,
            )
        )
    record_audit(
        db,
        request.app.state.json_log,
        actor=session.user.username,
        action="log_ingest",
        target=str(len(body.lines)),
        src_ip=client_ip(request),
    )
    return {"results": results}


@router.get("/inventory/ports")
def ports(request: Request, db: Session = Depends(db_session)):
    require_user(request, db)
    settings = request.app.state.settings
    return {
        "listeners": read_host_listeners(),
        "note": REACHABILITY_NOTE,
        "warning": inventory_warning(host_network=settings.host_network, nft_backend=settings.nft_backend),
        "host_network": settings.host_network,
        "ssh_port": settings.ssh_port,
        "excluded_ports": settings.excluded_ports,
    }


@router.post("/inventory/reachability")
def reachability(body: ReachabilityIn, request: Request, db: Session = Depends(db_session)):
    session = require_user(request, db)

    def act():
        result = check_reachability(
            body.host,
            body.port,
            request.app.state.settings.reachability_targets,
        )
        record_audit(
            db,
            request.app.state.json_log,
            actor=session.user.username,
            action="reachability_check",
            target=f"{body.host}:{body.port}",
            src_ip=client_ip(request),
        )
        record_event(
            db,
            request.app.state.json_log,
            "reachability",
            src_ip=body.host,
            dst_port=body.port,
            action="probe" if result["tcp_connect"] else "closed",
        )
        return result

    return api_error(act)


@router.get("/events")
def events(request: Request, db: Session = Depends(db_session), limit: int = Query(default=100, ge=1, le=500)):
    require_user(request, db)
    rows = db.scalars(select(Event).order_by(Event.id.desc()).limit(limit)).all()
    return {"events": [event_dict(row) for row in rows], "retention_days": request.app.state.settings.log_retention_days}


@router.get("/events/export")
def export_events(request: Request, db: Session = Depends(db_session), limit: int = Query(default=1000, ge=1, le=5000)):
    require_user(request, db)
    rows = db.scalars(select(Event).order_by(Event.id.asc()).limit(limit)).all()
    payload = "".join(json.dumps(event_dict(row), separators=(",", ":")) + "\n" for row in rows)
    record_audit(
        db,
        request.app.state.json_log,
        actor=require_user(request, db).user.username,
        action="events_export",
        target=str(len(rows)),
        src_ip=client_ip(request),
    )
    return Response(content=payload, media_type="application/x-ndjson")


@router.get("/audit")
def audit(request: Request, db: Session = Depends(db_session), limit: int = Query(default=100, ge=1, le=500)):
    require_user(request, db)
    rows = db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(limit)).all()
    return {"audit": [_audit_dict(row) for row in rows], "retention_days": request.app.state.settings.log_retention_days}


@router.get("/honeypots")
def honeypots(request: Request, db: Session = Depends(db_session)):
    require_user(request, db)
    rows = db.scalars(select(Honeypot).order_by(Honeypot.name)).all()
    directory = request.app.state.settings.data_dir / "honeypot"
    return {
        "label": "Decoys are opt-in, low-interaction, and isolated. They do not run commands or probe remote hosts.",
        "honeypots": [honeypot_dict(row) for row in rows],
        "telemetry": read_telemetry(directory),
        "start_hint": "docker compose --profile honeypots up -d",
    }


@router.post("/honeypots/{name}/enable")
def enable_honeypot(name: str, request: Request, db: Session = Depends(db_session)):
    return _toggle(name, True, request, db)


@router.post("/honeypots/{name}/disable")
def disable_honeypot(name: str, request: Request, db: Session = Depends(db_session)):
    return _toggle(name, False, request, db)


def _toggle(name: str, enabled: bool, request: Request, db: Session):
    session = require_user(request, db)
    row = db.scalar(select(Honeypot).where(Honeypot.name == name))
    if row is None:
        raise HTTPException(status_code=404, detail="Honeypot not found")
    row.enabled = enabled
    directory = request.app.state.settings.data_dir / "honeypot"
    write_desired(db, directory)
    record_audit(
        db,
        request.app.state.json_log,
        actor=session.user.username,
        action="honeypot_enable" if enabled else "honeypot_disable",
        target=row.name,
        src_ip=client_ip(request),
    )
    return {
        "honeypot": honeypot_dict(row),
        "containers_started": False,
        "notice": (
            "Desired state was saved. This does not start a container and does not attach the Docker socket. "
            "On a host you administer, start the opt-in profile with docker compose --profile honeypots up -d."
        ),
    }

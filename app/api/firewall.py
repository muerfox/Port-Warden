from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import api_error, client_ip, db_session, require_user
from app.models import IpList, IpListEntry, Rule
from app.schemas import ApplyIn, EntryIn, ListIn, ModeIn, RuleIn, RulePatch
from app.serialize import entry_dict, list_dict, rule_dict
from app.services.events import record_audit
from app.services.firewall.engine import set_setting
from app.services.firewall.presets import PRESETS
from app.services.firewall.protections import (
    disable_protection,
    enable_protection,
    enable_recommended,
    list_protection_status,
)
from app.services.records import add_entry, create_list, create_rule, update_rule

router = APIRouter(tags=["firewall"])


def _entries(db: Session, list_id: int) -> list[IpListEntry]:
    return list(db.scalars(select(IpListEntry).where(IpListEntry.list_id == list_id).order_by(IpListEntry.id)))


@router.get("/presets")
def presets(request: Request, db: Session = Depends(db_session)):
    require_user(request, db)
    return {
        "presets": PRESETS,
        "note": "Presets are templates. Saving a preset is a separate action and does not open a port by itself.",
    }


@router.get("/protections")
def protections(request: Request, db: Session = Depends(db_session)):
    require_user(request, db)
    return {
        "packs": list_protection_status(db),
        "note": "Protection packs install deny rules into desired state. Preview/Apply is still required.",
    }


@router.post("/protections/enable-recommended")
def protections_enable_recommended(request: Request, db: Session = Depends(db_session)):
    session = require_user(request, db)

    def act():
        result = enable_recommended(db)
        record_audit(
            db,
            request.app.state.json_log,
            actor=session.user.username,
            action="protections_enable_recommended",
            target="recommended",
            src_ip=client_ip(request),
        )
        return result

    return api_error(act)


@router.post("/protections/{pack_id}/enable")
def protections_enable(pack_id: str, request: Request, db: Session = Depends(db_session)):
    session = require_user(request, db)

    def act():
        result = enable_protection(db, pack_id)
        record_audit(
            db,
            request.app.state.json_log,
            actor=session.user.username,
            action="protection_enable",
            target=pack_id,
            src_ip=client_ip(request),
        )
        return result

    return api_error(act)


@router.post("/protections/{pack_id}/disable")
def protections_disable(pack_id: str, request: Request, db: Session = Depends(db_session)):
    session = require_user(request, db)

    def act():
        result = disable_protection(db, pack_id)
        record_audit(
            db,
            request.app.state.json_log,
            actor=session.user.username,
            action="protection_disable",
            target=pack_id,
            src_ip=client_ip(request),
        )
        return result

    return api_error(act)


@router.get("/rules")
def list_rules(request: Request, db: Session = Depends(db_session)):
    require_user(request, db)
    rows = db.scalars(select(Rule).order_by(Rule.priority, Rule.name)).all()
    return {"rules": [rule_dict(row) for row in rows]}


@router.post("/rules")
def post_rule(body: RuleIn, request: Request, db: Session = Depends(db_session)):
    session = require_user(request, db)

    def act():
        row = create_rule(db, body.model_dump())
        record_audit(
            db,
            request.app.state.json_log,
            actor=session.user.username,
            action="rule_create",
            target=row.name,
            src_ip=client_ip(request),
        )
        return rule_dict(row)

    return api_error(act)


@router.patch("/rules/{rule_id}")
def patch_rule(rule_id: int, body: RulePatch, request: Request, db: Session = Depends(db_session)):
    session = require_user(request, db)
    row = db.get(Rule, rule_id)
    if row is None:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="Rule not found")

    def act():
        update_rule(db, row, body.model_dump(exclude_unset=True))
        record_audit(
            db,
            request.app.state.json_log,
            actor=session.user.username,
            action="rule_update",
            target=row.name,
            src_ip=client_ip(request),
        )
        return rule_dict(row)

    return api_error(act)


@router.delete("/rules/{rule_id}")
def delete_rule(rule_id: int, request: Request, db: Session = Depends(db_session)):
    session = require_user(request, db)
    row = db.get(Rule, rule_id)
    if row is None:
        from fastapi import HTTPException

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
    return {"ok": True}


@router.get("/lists")
def get_lists(request: Request, db: Session = Depends(db_session)):
    require_user(request, db)
    rows = db.scalars(select(IpList).order_by(IpList.name)).all()
    return {"lists": [list_dict(row, _entries(db, row.id)) for row in rows]}


@router.post("/lists")
def post_list(body: ListIn, request: Request, db: Session = Depends(db_session)):
    session = require_user(request, db)

    def act():
        row = create_list(db, body.name, body.kind, body.comment)
        record_audit(
            db,
            request.app.state.json_log,
            actor=session.user.username,
            action="list_create",
            target=row.name,
            src_ip=client_ip(request),
        )
        return list_dict(row, [])

    return api_error(act)


@router.post("/lists/{list_id}/entries")
def post_entry(list_id: int, body: EntryIn, request: Request, db: Session = Depends(db_session)):
    session = require_user(request, db)
    ip_list = db.get(IpList, list_id)
    if ip_list is None:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="List not found")

    def act():
        row = add_entry(db, ip_list, body.cidr, body.comment, body.expires_at, request.app.state.settings)
        record_audit(
            db,
            request.app.state.json_log,
            actor=session.user.username,
            action="list_entry_add",
            target=f"{ip_list.name}:{row.cidr}",
            src_ip=client_ip(request),
        )
        return entry_dict(row)

    return api_error(act)


@router.delete("/lists/{list_id}")
def delete_list(list_id: int, request: Request, db: Session = Depends(db_session)):
    session = require_user(request, db)
    ip_list = db.get(IpList, list_id)
    if ip_list is None:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="List not found")
    if ip_list.builtin:
        from fastapi import HTTPException

        raise HTTPException(status_code=400, detail="Built-in lists cannot be deleted")
    name = ip_list.name
    db.delete(ip_list)
    record_audit(
        db,
        request.app.state.json_log,
        actor=session.user.username,
        action="list_delete",
        target=name,
        src_ip=client_ip(request),
    )
    return {"ok": True}


@router.delete("/entries/{entry_id}")
def delete_entry(entry_id: int, request: Request, db: Session = Depends(db_session)):
    session = require_user(request, db)
    row = db.get(IpListEntry, entry_id)
    if row is None:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="Entry not found")
    target = row.cidr
    db.delete(row)
    record_audit(
        db,
        request.app.state.json_log,
        actor=session.user.username,
        action="list_entry_delete",
        target=target,
        src_ip=client_ip(request),
    )
    return {"ok": True}


@router.post("/firewall/mode")
def firewall_mode(body: ModeIn, request: Request, db: Session = Depends(db_session)):
    session = require_user(request, db)

    def act():
        if body.mode == "monitor" and not body.monitor_ack:
            raise ValueError(
                "Monitor mode can accept traffic before a later host firewall runs. "
                "Set monitor_ack to true to store this mode. It is not applied until you preview and apply."
            )
        set_setting(db, "firewall_mode", body.mode)
        record_audit(
            db,
            request.app.state.json_log,
            actor=session.user.username,
            action="firewall_mode",
            target=body.mode,
            src_ip=client_ip(request),
        )
        return {"mode": body.mode, "applied": False}

    return api_error(act)


@router.post("/firewall/preview")
def firewall_preview(request: Request, db: Session = Depends(db_session)):
    session = require_user(request, db)
    preview = request.app.state.engine.preview(db, client_ip(request))
    record_audit(
        db,
        request.app.state.json_log,
        actor=session.user.username,
        action="firewall_preview",
        target=preview.sha256[:12],
        src_ip=client_ip(request),
    )
    return {
        "script": preview.script,
        "sha256": preview.sha256,
        "confirm_token": preview.confirm_token,
        "lockout_risk": preview.lockout_risk,
        "lockout_reason": preview.lockout_reason,
        "warnings": preview.warnings,
        "diff": preview.diff,
        "mode": preview.mode,
        "backend": preview.backend,
        "enforces": preview.enforces,
        "lockout_phrase": "I_UNDERSTAND_LOCKOUT",
    }


@router.post("/firewall/apply")
def firewall_apply(body: ApplyIn, request: Request, db: Session = Depends(db_session)):
    session = require_user(request, db)

    def act():
        result = request.app.state.engine.apply(db, body.confirm_token, client_ip(request), body.lockout_phrase)
        record_audit(
            db,
            request.app.state.json_log,
            actor=session.user.username,
            action="firewall_apply",
            target=result["status"],
            src_ip=client_ip(request),
            details={"sha256": result["sha256"], "applied": result["applied"]},
        )
        return result

    return api_error(act)


@router.post("/firewall/rollback")
def firewall_rollback(request: Request, db: Session = Depends(db_session)):
    session = require_user(request, db)

    def act():
        result = request.app.state.engine.rollback(db, client_ip(request))
        record_audit(
            db,
            request.app.state.json_log,
            actor=session.user.username,
            action="firewall_rollback",
            target=result["sha256"][:12],
            src_ip=client_ip(request),
        )
        return result

    return api_error(act)


@router.get("/firewall/status")
def firewall_status(request: Request, db: Session = Depends(db_session)):
    require_user(request, db)
    status = request.app.state.engine.status(db)
    status["limitations"] = [
        "Docker does not, by itself, enforce the host firewall.",
        "Stopping this service leaves the last successfully applied nftables table in place.",
        "Startup does not flush or replace host firewall rules.",
        "External reachability depends on routers, NAT, and cloud security groups.",
    ]
    return status

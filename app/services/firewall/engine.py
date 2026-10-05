from __future__ import annotations

import difflib
import hashlib
import time
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings
from app.logging_json import JsonLogger
from app.models import AppSetting, Ban, IpList, IpListEntry, Rule, Snapshot
from app.security import issue_confirm_token, read_confirm_token
from app.services.firewall.backend import DisabledBackend, NftError
from app.services.firewall.render import Policy, Rendered, RuleView, render_policy
from app.services.firewall.safeguard import evaluate_lockout
from app.timeutil import is_expired, iso, utcnow

LOCKOUT_PHRASE = "I_UNDERSTAND_LOCKOUT"


class LockoutError(Exception):
    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


@dataclass
class Preview:
    script: str
    sha256: str
    confirm_token: str
    lockout_risk: bool
    lockout_reason: str
    warnings: list[str]
    diff: str
    mode: str
    backend: str
    enforces: bool


def script_sha(script: str) -> str:
    return hashlib.sha256(script.encode("utf-8")).hexdigest()


def get_setting(db: Session, key: str, default: str | None = None) -> str | None:
    row = db.get(AppSetting, key)
    return row.value if row else default


def set_setting(db: Session, key: str, value: str) -> None:
    row = db.get(AppSetting, key)
    if row is None:
        db.add(AppSetting(key=key, value=value))
    else:
        row.value = value
    db.flush()


class FirewallEngine:
    def __init__(self, settings: Settings, backend, json_log: JsonLogger) -> None:
        self.settings = settings
        self.backend = backend
        self.json_log = json_log
        self.last_good: str | None = None

    @property
    def enforces(self) -> bool:
        return not isinstance(self.backend, DisabledBackend)

    def load_last_good(self, db: Session) -> None:
        snap = db.scalars(
            select(Snapshot).where(Snapshot.applied.is_(True)).order_by(Snapshot.id.desc())
        ).first()
        if snap is not None:
            self.last_good = snap.script
            return
        path = self.settings.data_dir / "last-good.nft"
        if path.is_file():
            self.last_good = path.read_text(encoding="utf-8")

    def load_policy(self, db: Session, now=None) -> Policy:
        now = now or utcnow()
        mode = get_setting(db, "firewall_mode", self.settings.firewall_mode) or self.settings.firewall_mode
        allow: list[str] = []
        deny: list[str] = []
        lists = db.scalars(select(IpList)).all()
        for ip_list in lists:
            entries = db.scalars(select(IpListEntry).where(IpListEntry.list_id == ip_list.id)).all()
            for entry in entries:
                if is_expired(entry.expires_at, now):
                    continue
                if ip_list.kind == "allow":
                    allow.append(entry.cidr)
                elif ip_list.kind == "deny":
                    deny.append(entry.cidr)
        bans = []
        for ban in db.scalars(select(Ban).where(Ban.lifted_at.is_(None))).all():
            if ban.permanent or not is_expired(ban.expires_at, now):
                bans.append(ban.ip)
        rules = [
            RuleView(
                name=row.name,
                action=row.action,
                direction=row.direction,
                protocol=row.protocol,
                src_cidr=row.src_cidr,
                dst_cidr=row.dst_cidr,
                ports=row.ports,
                comment=row.comment,
                priority=row.priority,
                enabled=row.enabled,
                expires_at=row.expires_at,
            )
            for row in db.scalars(select(Rule)).all()
        ]
        from app.services.inventory.workspace import effective_open_ports, effective_ssh_port

        return Policy(
            mode=mode,
            management_cidrs=list(self.settings.management_cidrs),
            ssh_port=effective_ssh_port(db, self.settings),
            excluded_ports=effective_open_ports(db, self.settings),
            allow_cidrs=allow,
            deny_cidrs=deny,
            ban_cidrs=bans,
            rules=rules,
        )

    def render(self, db: Session, now=None) -> Rendered:
        now = now or utcnow()
        return render_policy(self.load_policy(db, now), now)

    def preview(self, db: Session, admin_ip: str) -> Preview:
        rendered = self.render(db)
        policy = self.load_policy(db)
        risk, reason = evaluate_lockout(policy, admin_ip)
        digest = script_sha(rendered.script)
        token = issue_confirm_token(
            self.settings.secret_key,
            {
                "sha": digest,
                "exp": int(time.time()) + 300,
                "admin_ip": admin_ip,
                "mode": policy.mode,
            },
        )
        previous = self._latest_script(db)
        diff = "\n".join(
            difflib.unified_diff(
                (previous or "").splitlines(),
                rendered.script.splitlines(),
                fromfile="last-snapshot",
                tofile="desired",
                lineterm="",
            )
        )
        warnings = list(rendered.warnings)
        if risk:
            warnings.append(reason)
        if not self.enforces:
            warnings.append("The nft backend is disabled. Apply stores a snapshot and does not change the host.")
        self.json_log.emit(
            "firewall_preview",
            action="preview",
            src_ip=admin_ip,
            rule_id="",
            dst_port=self.settings.ssh_port,
            mode=policy.mode,
            sha256=digest,
        )
        return Preview(
            script=rendered.script,
            sha256=digest,
            confirm_token=token,
            lockout_risk=risk,
            lockout_reason=reason,
            warnings=warnings,
            diff=diff,
            mode=policy.mode,
            backend=getattr(self.backend, "name", "unknown"),
            enforces=self.enforces,
        )

    def apply(self, db: Session, confirm_token: str, admin_ip: str, lockout_phrase: str) -> dict:
        payload = read_confirm_token(self.settings.secret_key, confirm_token)
        if payload.get("admin_ip") != admin_ip:
            raise ValueError("client IP changed since preview; preview again")
        rendered = self.render(db)
        digest = script_sha(rendered.script)
        if payload.get("sha") != digest:
            raise ValueError("rules changed since preview; preview again")
        policy = self.load_policy(db)
        if payload.get("mode") != policy.mode:
            raise ValueError("firewall mode changed since preview; preview again")
        risk, reason = evaluate_lockout(policy, admin_ip)
        if risk and lockout_phrase != LOCKOUT_PHRASE:
            raise LockoutError(reason + f" Type {LOCKOUT_PHRASE} to apply anyway.")
        if self.enforces:
            self.push(rendered.script)
            applied = True
            label = "applied"
        else:
            staged = self.settings.data_dir / "staged.nft"
            staged.write_text(rendered.script, encoding="utf-8")
            applied = False
            label = "staged"
        self._save_snapshot(db, rendered.script, digest, applied, label)
        self.json_log.emit(
            "firewall_apply",
            action=label,
            src_ip=admin_ip,
            rule_id="",
            dst_port=self.settings.ssh_port,
            sha256=digest,
            mode=policy.mode,
        )
        return {
            "status": label,
            "applied": applied,
            "sha256": digest,
            "warnings": rendered.warnings,
            "lockout_override": bool(risk),
        }

    def push(self, script: str) -> None:
        """Install a script. On failure, re-apply the last good script when one exists."""
        self.backend.check(script)
        try:
            self.backend.apply(script)
        except Exception as exc:
            restored = False
            restore_error = ""
            if self.last_good:
                try:
                    self.backend.apply(self.last_good)
                    restored = True
                except Exception as restore_exc:  # noqa: BLE001
                    restore_error = str(restore_exc)
            self.json_log.emit(
                "firewall_apply_failed",
                action="rollback" if restored else "failed",
                src_ip="",
                rule_id="",
                error=str(exc)[:300],
                restore_error=restore_error[:300],
            )
            if restore_error:
                raise NftError(f"apply failed and rollback failed: {restore_error}") from exc
            if restored:
                raise NftError(f"apply failed; previous ruleset restored: {exc}") from exc
            raise NftError(f"apply failed; host ruleset unchanged: {exc}") from exc
        self.last_good = script
        path = self.settings.data_dir / "last-good.nft"
        path.write_text(script, encoding="utf-8")

    def rollback(self, db: Session, admin_ip: str) -> dict:
        snaps = list(
            db.scalars(select(Snapshot).where(Snapshot.applied.is_(True)).order_by(Snapshot.id.desc()).limit(2))
        )
        if len(snaps) < 2:
            raise ValueError("no previous applied snapshot to roll back to")
        target = snaps[1]
        if self.enforces:
            self.push(target.script)
        else:
            raise ValueError("nft backend is disabled; rollback would not change the host")
        digest = script_sha(target.script)
        self._save_snapshot(db, target.script, digest, True, "rollback")
        self.json_log.emit(
            "firewall_rollback",
            action="rollback",
            src_ip=admin_ip,
            rule_id="",
            sha256=digest,
        )
        return {"status": "rolled_back", "sha256": digest, "snapshot_id": target.id}

    def status(self, db: Session) -> dict:
        rendered = self.render(db)
        desired = script_sha(rendered.script)
        latest = db.scalars(select(Snapshot).order_by(Snapshot.id.desc())).first()
        applied = db.scalars(
            select(Snapshot).where(Snapshot.applied.is_(True)).order_by(Snapshot.id.desc())
        ).first()
        dump = None
        host_error = ""
        if self.enforces:
            try:
                dump = self.backend.dump_table()
            except NftError as exc:
                host_error = str(exc)
        host_present = None if dump is None else bool(dump.strip())
        missing = []
        if dump:
            for rule in self.load_policy(db).rules:
                if rule.enabled and not is_expired(rule.expires_at) and f"pw:{rule.name}" not in dump:
                    missing.append(rule.name)
        drift = (applied is not None and applied.sha256 != desired) or bool(missing)
        warnings = list(rendered.warnings)
        if self.settings.secret_key.startswith("change-me"):
            warnings.append("PORT_WARDEN_SECRET_KEY is still the sample default.")
        if host_error:
            warnings.append(f"Could not read the host table: {host_error}")
        return {
            "backend": getattr(self.backend, "name", "unknown"),
            "enforces": self.enforces,
            "mode": self.load_policy(db).mode,
            "desired_sha256": desired,
            "applied_sha256": applied.sha256 if applied else None,
            "latest_label": latest.label if latest else None,
            "drift": drift,
            "installed": applied is not None,
            "host_table_present": host_present,
            "missing_on_host": missing,
            "warnings": warnings,
            "generated_at": iso(utcnow()),
        }

    def maybe_auto_apply(self, db: Session, previous_sha: str) -> bool:
        if not self.settings.ban_auto_apply or not self.enforces:
            return False
        applied = db.scalars(
            select(Snapshot).where(Snapshot.applied.is_(True)).order_by(Snapshot.id.desc())
        ).first()
        if applied is None or applied.sha256 != previous_sha:
            self.json_log.emit(
                "ban_auto_apply_skipped",
                action="skipped",
                src_ip="",
                rule_id="",
                reason="pending firewall drift",
            )
            return False
        rendered = self.render(db)
        self.push(rendered.script)
        digest = script_sha(rendered.script)
        self._save_snapshot(db, rendered.script, digest, True, "auto-ban")
        self.json_log.emit("ban_auto_apply", action="applied", src_ip="", rule_id="", sha256=digest)
        return True

    def _latest_script(self, db: Session) -> str | None:
        snap = db.scalars(select(Snapshot).order_by(Snapshot.id.desc())).first()
        return snap.script if snap else None

    def _save_snapshot(self, db: Session, script: str, digest: str, applied: bool, label: str) -> None:
        db.add(
            Snapshot(
                created_at=utcnow(),
                label=label,
                script=script,
                sha256=digest,
                applied=applied,
            )
        )
        stamp = utcnow().strftime("%Y%m%dT%H%M%SZ")
        path = self.settings.data_dir / "snapshots" / f"{stamp}-{digest[:12]}.nft"
        path.write_text(script, encoding="utf-8")
        db.flush()

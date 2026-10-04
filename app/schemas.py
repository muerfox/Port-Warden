from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class LoginIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=200)
    totp: str | None = Field(default=None, max_length=12)


class PasswordIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    password: str = Field(min_length=1, max_length=200)
    totp: str | None = None


class TotpConfirm(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: str = Field(min_length=6, max_length=8)


class RuleIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    action: Literal["allow", "deny"]
    direction: Literal["in", "out"]
    protocol: Literal["tcp", "udp", "icmp", "any"]
    src_cidr: str | None = None
    dst_cidr: str | None = None
    ports: str | None = None
    comment: str = ""
    priority: int = 100
    enabled: bool = True
    expires_at: datetime | None = None


class RulePatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = None
    action: Literal["allow", "deny"] | None = None
    direction: Literal["in", "out"] | None = None
    protocol: Literal["tcp", "udp", "icmp", "any"] | None = None
    src_cidr: str | None = None
    dst_cidr: str | None = None
    ports: str | None = None
    comment: str | None = None
    priority: int | None = None
    enabled: bool | None = None
    expires_at: datetime | None = None


class ListIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    kind: Literal["allow", "deny"]
    comment: str = ""


class EntryIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cidr: str
    comment: str = ""
    expires_at: datetime | None = None


class BanIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ip: str
    reason: str = "manual"
    permanent: bool = False
    seconds: int | None = 3600


class ApplyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirm_token: str
    lockout_phrase: str = ""


class ModeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["enforce", "monitor"]
    monitor_ack: bool = False


class IngestIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    lines: list[str] = Field(max_length=500)


class BfSettingsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    threshold: int = Field(ge=1, le=100)
    window_seconds: int = Field(ge=10, le=86400)
    ban_seconds: int = Field(ge=60, le=31_536_000)
    cooldown_seconds: int = Field(ge=0, le=86400)
    permanent_after: int = Field(ge=0, le=100)


class ReachabilityIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    host: str
    port: int = Field(ge=1, le=65535)

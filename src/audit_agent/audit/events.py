"""Audit event models (schema v1.0).

The field reference is in ``docs/AUDIT_SCHEMA.md``. An event moves through two stages:

1. ``AuditEventBody``: the event content, built by the logger and then redacted.
2. ``AuditEvent``: the body plus chain fields (``seq``, ``prev_hash``, ``hash``),
   assigned when the event is appended to the store.

Both models are frozen. Audit events are never mutated once built.
"""

import re
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SCHEMA_VERSION = "1.0"
GENESIS_HASH = "0" * 64
MAX_PREVIEW_CHARS = 500

_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
_HASH_PATTERN = r"^[0-9a-f]{64}$"


def utc_now_iso() -> str:
    """Current UTC time as ISO-8601 with millisecond precision and a ``Z`` suffix."""
    now = datetime.now(UTC)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def new_id() -> str:
    """New random UUID4 string, used for event and run IDs."""
    return str(uuid.uuid4())


class EventType(StrEnum):
    USER_REQUEST = "user_request"
    TOOL_CALL = "tool_call"
    DATA_ACCESS = "data_access"
    DECISION = "decision"
    FINAL_RESPONSE = "final_response"
    ERROR = "error"


class Actor(StrEnum):
    USER = "user"
    AGENT = "agent"
    TOOL = "tool"
    SYSTEM = "system"


class Status(StrEnum):
    OK = "ok"
    ERROR = "error"
    DENIED = "denied"


class DataOperation(StrEnum):
    READ = "read"
    WRITE = "write"


_MODEL_CONFIG = ConfigDict(frozen=True, extra="forbid", protected_namespaces=())


class TokenUsage(BaseModel):
    """Token counts for the model call behind an event."""

    model_config = _MODEL_CONFIG

    input: int = Field(ge=0)
    output: int = Field(ge=0)


class ErrorInfo(BaseModel):
    """Structured error details. ``message`` must already be redacted."""

    model_config = _MODEL_CONFIG

    type: str = Field(min_length=1)
    message: str


# Fields that must be set (not None) for each event type.
_REQUIRED_FIELDS: dict[EventType, tuple[str, ...]] = {
    EventType.USER_REQUEST: ("content",),
    EventType.TOOL_CALL: ("tool_name", "rationale"),
    EventType.DATA_ACCESS: ("tool_name", "data_source", "data_operation"),
    EventType.DECISION: ("decision",),
    EventType.FINAL_RESPONSE: ("content",),
    EventType.ERROR: ("error",),
}


class AuditEventBody(BaseModel):
    """Event content before it is hash-chained."""

    model_config = _MODEL_CONFIG

    schema_version: str = SCHEMA_VERSION
    event_id: str = Field(default_factory=new_id)
    run_id: str
    step_id: int = Field(ge=0)
    timestamp: str = Field(default_factory=utc_now_iso)
    event_type: EventType
    actor: Actor
    status: Status = Status.OK

    model: str | None = None
    tool_name: str | None = None
    tool_args: dict[str, Any] | None = None
    result_preview: str | None = Field(default=None, max_length=MAX_PREVIEW_CHARS)

    data_source: str | None = None
    data_operation: DataOperation | None = None
    records_touched: int | None = Field(default=None, ge=0)
    fields_accessed: list[str] | None = None

    decision: str | None = None
    rationale: str | None = None
    model_explanation: str | None = None
    content: str | None = None

    error: ErrorInfo | None = None
    latency_ms: float | None = Field(default=None, ge=0)
    tokens: TokenUsage | None = None
    redactions: list[str] = Field(default_factory=list)

    @field_validator("schema_version")
    @classmethod
    def _check_schema_version(cls, value: str) -> str:
        if value != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema_version {value!r}; expected {SCHEMA_VERSION!r}")
        return value

    @field_validator("event_id", "run_id")
    @classmethod
    def _check_uuid(cls, value: str) -> str:
        try:
            uuid.UUID(value)
        except ValueError as exc:
            raise ValueError(f"not a valid UUID: {value!r}") from exc
        return value

    @field_validator("timestamp")
    @classmethod
    def _check_timestamp(cls, value: str) -> str:
        if not _TIMESTAMP_RE.match(value):
            raise ValueError(
                "timestamp must be UTC ISO-8601 with ms, e.g. 2026-10-06T10:33:12.481Z"
            )
        return value

    @field_validator("redactions")
    @classmethod
    def _normalize_redactions(cls, value: list[str]) -> list[str]:
        return sorted(set(value))

    @model_validator(mode="after")
    def _check_invariants(self) -> Self:
        missing = [
            name for name in _REQUIRED_FIELDS[self.event_type] if getattr(self, name) is None
        ]
        if missing:
            raise ValueError(f"{self.event_type.value} event requires: {', '.join(missing)}")
        if self.event_type is EventType.TOOL_CALL and not (self.rationale or "").strip():
            raise ValueError("tool_call event requires a non-empty rationale")
        if self.status is Status.DENIED and self.event_type is not EventType.TOOL_CALL:
            raise ValueError("status 'denied' is only valid for tool_call events")
        if self.event_type is EventType.ERROR and self.status is not Status.ERROR:
            raise ValueError("error events must have status 'error'")
        if self.status is not Status.OK and self.error is None:
            raise ValueError(f"status '{self.status.value}' requires error info")
        return self


class AuditEvent(AuditEventBody):
    """A persisted, hash-chained audit event."""

    seq: int = Field(ge=1)
    prev_hash: str = Field(pattern=_HASH_PATTERN)
    hash: str = Field(pattern=_HASH_PATTERN)

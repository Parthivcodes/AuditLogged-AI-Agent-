"""Tests for audit/events.py: schema validation and per-event-type invariants."""

import re
import uuid
from typing import Any

import pytest
from pydantic import ValidationError

from audit_agent.audit.events import (
    GENESIS_HASH,
    MAX_PREVIEW_CHARS,
    SCHEMA_VERSION,
    Actor,
    AuditEvent,
    AuditEventBody,
    DataOperation,
    ErrorInfo,
    EventType,
    Status,
    TokenUsage,
    utc_now_iso,
)

RUN_ID = str(uuid.uuid4())

VALID_BY_TYPE: dict[EventType, dict[str, Any]] = {
    EventType.USER_REQUEST: {"actor": Actor.USER, "content": "Summarize Q1 sales data"},
    EventType.DECISION: {"actor": Actor.AGENT, "decision": "call_tool:read_sales_data"},
    EventType.TOOL_CALL: {
        "actor": Actor.TOOL,
        "tool_name": "read_sales_data",
        "rationale": "Need rows.",
    },
    EventType.DATA_ACCESS: {
        "actor": Actor.TOOL,
        "tool_name": "read_sales_data",
        "data_source": "data/sample/sales_q1.csv",
        "data_operation": DataOperation.READ,
    },
    EventType.FINAL_RESPONSE: {"actor": Actor.AGENT, "content": "Q1 revenue was $482,310."},
    EventType.ERROR: {
        "actor": Actor.SYSTEM,
        "status": Status.ERROR,
        "error": ErrorInfo(type="RuntimeError", message="boom"),
    },
}


def make_body(event_type: EventType = EventType.USER_REQUEST, **overrides: Any) -> AuditEventBody:
    fields: dict[str, Any] = {"run_id": RUN_ID, "step_id": 0, "event_type": event_type}
    fields.update(VALID_BY_TYPE[event_type])
    fields.update(overrides)
    return AuditEventBody(**fields)


@pytest.mark.parametrize("event_type", list(EventType))
def test_valid_event_of_each_type(event_type: EventType) -> None:
    body = make_body(event_type)
    assert body.event_type is event_type


def test_defaults_are_populated() -> None:
    body = make_body()
    assert body.schema_version == SCHEMA_VERSION
    assert uuid.UUID(body.event_id).version == 4
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", body.timestamp)
    assert body.status is Status.OK
    assert body.redactions == []


def test_utc_now_iso_format() -> None:
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", utc_now_iso())


def test_json_dump_uses_plain_strings_for_enums() -> None:
    body = make_body(EventType.DATA_ACCESS, records_touched=60, fields_accessed=["region"])
    dumped = body.model_dump(mode="json")
    assert dumped["event_type"] == "data_access"
    assert dumped["actor"] == "tool"
    assert dumped["data_operation"] == "read"
    assert dumped["status"] == "ok"


def test_models_are_frozen() -> None:
    body = make_body()
    with pytest.raises(ValidationError):
        body.content = "tampered"  # type: ignore[misc]


def test_unknown_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        make_body(chain_of_thought="hidden reasoning")


@pytest.mark.parametrize(
    "overrides",
    [
        {"run_id": "not-a-uuid"},
        {"event_id": "123"},
        {"timestamp": "2026-10-06 10:33:12"},
        {"timestamp": "2026-10-06T10:33:12Z"},
        {"schema_version": "2.0"},
        {"step_id": -1},
        {"records_touched": -5},
        {"latency_ms": -0.1},
        {"result_preview": "x" * (MAX_PREVIEW_CHARS + 1)},
        {"tokens": {"input": -1, "output": 0}},
    ],
)
def test_invalid_field_values_are_rejected(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        make_body(**overrides)


@pytest.mark.parametrize(
    ("event_type", "field"),
    [
        (EventType.USER_REQUEST, "content"),
        (EventType.DECISION, "decision"),
        (EventType.TOOL_CALL, "tool_name"),
        (EventType.TOOL_CALL, "rationale"),
        (EventType.DATA_ACCESS, "tool_name"),
        (EventType.DATA_ACCESS, "data_source"),
        (EventType.DATA_ACCESS, "data_operation"),
        (EventType.FINAL_RESPONSE, "content"),
        (EventType.ERROR, "error"),
    ],
)
def test_required_fields_per_event_type(event_type: EventType, field: str) -> None:
    with pytest.raises(ValidationError, match="requires"):
        make_body(event_type, **{field: None})


def test_tool_call_rejects_blank_rationale() -> None:
    with pytest.raises(ValidationError, match="non-empty rationale"):
        make_body(EventType.TOOL_CALL, rationale="   ")


def test_denied_tool_call_requires_error_info() -> None:
    with pytest.raises(ValidationError, match="requires error info"):
        make_body(EventType.TOOL_CALL, status=Status.DENIED)
    denied = make_body(
        EventType.TOOL_CALL,
        status=Status.DENIED,
        decision="deny:export_customer_list",
        error=ErrorInfo(type="PermissionDenied", message="not in allowlist"),
    )
    assert denied.status is Status.DENIED


def test_denied_is_only_valid_for_tool_calls() -> None:
    with pytest.raises(ValidationError, match="only valid for tool_call"):
        make_body(EventType.DECISION, status=Status.DENIED, error=ErrorInfo(type="X", message="y"))


def test_error_event_must_have_error_status() -> None:
    with pytest.raises(ValidationError, match="status 'error'"):
        make_body(EventType.ERROR, status=Status.OK)


def test_redactions_are_sorted_and_deduplicated() -> None:
    body = make_body(redactions=["phone", "email", "phone"])
    assert body.redactions == ["email", "phone"]


def test_token_usage_and_preview_at_limit() -> None:
    body = make_body(
        EventType.TOOL_CALL,
        result_preview="x" * MAX_PREVIEW_CHARS,
        tokens=TokenUsage(input=812, output=96),
    )
    assert body.tokens == TokenUsage(input=812, output=96)


# Chained event


def make_event(**overrides: Any) -> AuditEvent:
    fields: dict[str, Any] = make_body().model_dump()
    fields.update({"seq": 1, "prev_hash": GENESIS_HASH, "hash": "a" * 64})
    fields.update(overrides)
    return AuditEvent(**fields)


def test_audit_event_accepts_genesis_link() -> None:
    event = make_event()
    assert event.seq == 1
    assert event.prev_hash == GENESIS_HASH


@pytest.mark.parametrize(
    "overrides",
    [{"seq": 0}, {"prev_hash": "abc"}, {"hash": "Z" * 64}, {"hash": "A" * 64}],
)
def test_audit_event_rejects_bad_chain_fields(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        make_event(**overrides)


def test_audit_event_json_round_trip() -> None:
    event = make_event(tokens=TokenUsage(input=1, output=2), redactions=["email"])
    assert AuditEvent.model_validate_json(event.model_dump_json()) == event

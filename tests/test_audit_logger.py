"""Tests for audit/logger.py (build → redact → chain → store) and audit/timeline.py."""

import uuid
from pathlib import Path

import pytest

from audit_agent.audit.events import (
    MAX_PREVIEW_CHARS,
    Actor,
    DataOperation,
    ErrorInfo,
    EventType,
    Status,
    TokenUsage,
)
from audit_agent.audit.hashchain import event_hash
from audit_agent.audit.logger import AuditLogger, truncate
from audit_agent.audit.redaction import Redactor
from audit_agent.audit.timeline import render_timeline
from audit_agent.storage.sqlite_store import SQLiteAuditStore

EMAIL = "jane.doe@example.com"
API_KEY = "sk-ant-api03-SUPERSECRETvalue123"
PASSWORD = "hunter2-correct-horse"
CARD = "4111 1111 1111 1111"
SEEDED = (EMAIL, API_KEY, PASSWORD, CARD, "SUPERSECRET", "jane.doe")


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "audit.db"


@pytest.fixture
def store(db_path: Path):
    with SQLiteAuditStore(db_path) as s:
        yield s


@pytest.fixture
def logger(store: SQLiteAuditStore) -> AuditLogger:
    return AuditLogger(store)


def demo_run(logger: AuditLogger) -> str:
    """The PROJECT_BRIEF demo scenario, including a denied tool and seeded PII."""
    run = logger.new_run_id()
    model = "claude-test"
    logger.user_request(run, f"Summarize Q1 sales. Contact me at {EMAIL}")
    logger.decision(
        run,
        "call_tool:read_sales_data",
        rationale="Need the raw Q1 rows first.",
        model_explanation="I'll load the dataset.",
        model=model,
        tool_name="read_sales_data",
        latency_ms=1380.4,
        tokens=TokenUsage(input=812, output=96),
    )
    logger.data_access(
        run,
        "read_sales_data",
        "data/sample/sales_q1.csv",
        DataOperation.READ,
        records_touched=60,
        fields_accessed=["order_id", "revenue", "customer_email"],
    )
    logger.tool_call(
        run,
        "read_sales_data",
        {"dataset": "sales_q1", "rationale": "Need the raw Q1 rows first."},
        result_preview=f"60 rows; sample: {{order_id: 1001, customer_email: '{EMAIL}'}}",
        latency_ms=4.2,
    )
    logger.decision(run, "deny:export_customer_list", tool_name="export_customer_list")
    logger.tool_call(
        run,
        "export_customer_list",
        {"format": "csv", "rationale": "User may want top customers."},
        status=Status.DENIED,
        decision="deny:export_customer_list",
        error=ErrorInfo(type="PermissionDenied", message="not in the allowlist"),
    )
    logger.final_response(
        run, "Q1 revenue was $482,310.", model=model, tokens=TokenUsage(input=3420, output=388)
    )
    return run


# Round trip & step numbering


def test_events_round_trip_with_correct_fields_and_hashes(
    logger: AuditLogger, store: SQLiteAuditStore
) -> None:
    run = demo_run(logger)
    events = store.get_run_events(run)
    assert [e.step_id for e in events] == list(range(7))
    assert [e.event_type for e in events] == [
        EventType.USER_REQUEST, EventType.DECISION, EventType.DATA_ACCESS, EventType.TOOL_CALL,
        EventType.DECISION, EventType.TOOL_CALL, EventType.FINAL_RESPONSE,
    ]  # fmt: skip
    assert all(e.hash == event_hash(e) for e in events)
    assert store.verify().ok

    decision = events[1]
    assert decision.model == "claude-test" and decision.tokens == TokenUsage(input=812, output=96)
    access = events[2]
    assert (access.records_touched, access.data_operation) == (60, DataOperation.READ)
    assert access.fields_accessed == ["order_id", "revenue", "customer_email"]
    assert events[6].decision == "final_answer"


def test_log_returns_exactly_what_is_stored(logger: AuditLogger, store: SQLiteAuditStore) -> None:
    run = logger.new_run_id()
    returned = logger.user_request(run, "hello")
    assert store.get_run_events(run) == [returned]


def test_step_ids_are_per_run(logger: AuditLogger, store: SQLiteAuditStore) -> None:
    run_a, run_b = logger.new_run_id(), logger.new_run_id()
    logger.user_request(run_a, "a")
    logger.user_request(run_b, "b")
    logger.decision(run_a, "final_answer")
    assert [e.step_id for e in store.get_run_events(run_a)] == [0, 1]
    assert [e.step_id for e in store.get_run_events(run_b)] == [0]


def test_step_counter_resumes_from_store(db_path: Path) -> None:
    run = str(uuid.uuid4())
    with SQLiteAuditStore(db_path) as s:
        AuditLogger(s).user_request(run, "first")
    with SQLiteAuditStore(db_path) as s:
        second = AuditLogger(s).decision(run, "final_answer")
        assert second.step_id == 1 and s.verify().ok


def test_invalid_event_writes_nothing_and_keeps_step(
    logger: AuditLogger, store: SQLiteAuditStore
) -> None:
    run = logger.new_run_id()
    logger.user_request(run, "go")
    with pytest.raises(ValueError, match="rationale"):
        logger.tool_call(run, "read_sales_data", {"dataset": "sales_q1"})  # no rationale
    with pytest.raises(ValueError, match="rationale"):
        logger.tool_call(run, "read_sales_data", {"rationale": "   "})
    assert store.count() == 1
    assert logger.decision(run, "final_answer").step_id == 1


# Rationale handling


def test_rationale_is_moved_out_of_tool_args(logger: AuditLogger) -> None:
    event = logger.tool_call(logger.new_run_id(), "t", {"x": 1, "rationale": "because"})
    assert event.rationale == "because" and event.tool_args == {"x": 1}


def test_explicit_rationale_wins_and_is_still_stripped_from_args(logger: AuditLogger) -> None:
    event = logger.tool_call(
        logger.new_run_id(), "t", {"rationale": "from args"}, rationale="explicit"
    )
    assert event.rationale == "explicit" and event.tool_args == {}


def test_denied_tool_call_is_attributed_to_agent(logger: AuditLogger) -> None:
    event = logger.tool_call(
        logger.new_run_id(),
        "export_customer_list",
        {"rationale": "r"},
        status=Status.DENIED,
        error=ErrorInfo(type="PermissionDenied", message="no"),
    )
    assert (event.status, event.actor) == (Status.DENIED, Actor.AGENT)


# Redaction at the choke point


def test_seeded_secrets_never_reach_the_db(
    logger: AuditLogger, store: SQLiteAuditStore, db_path: Path
) -> None:
    run = logger.new_run_id()
    logger.user_request(run, f"My email is {EMAIL} and card {CARD}")
    logger.decision(
        run,
        "call_tool:lookup",
        rationale=f"Look up {EMAIL}",
        model_explanation=f"Using key {API_KEY}",
    )
    logger.tool_call(
        run,
        "lookup",
        {"api_key": API_KEY, "user": {"password": PASSWORD, "email": EMAIL}, "rationale": "r"},
        result_preview=f"found {EMAIL}",
    )
    logger.error(run, RuntimeError(f"auth failed: Authorization: Bearer {API_KEY}"))
    logger.final_response(run, f"Done. Reach {EMAIL}.")

    raw_bytes = db_path.read_bytes()
    for wal in db_path.parent.glob("audit.db-*"):
        raw_bytes += wal.read_bytes()
    for secret in SEEDED:
        assert secret.encode() not in raw_bytes, secret
    assert store.verify().ok


def test_redaction_tags_recorded_per_event(logger: AuditLogger) -> None:
    run = logger.new_run_id()
    clean = logger.user_request(run, "Summarize Q1 sales")
    tagged = logger.tool_call(
        run, "t", {"token": "abc12345", "rationale": "r"}, result_preview=f"mail {EMAIL}"
    )
    err = logger.error(run, ErrorInfo(type="E", message=f"key {API_KEY}"))
    assert clean.redactions == []
    assert tagged.redactions == ["email", "secret"]
    assert tagged.tool_args == {"token": "[REDACTED:secret]"}
    assert tagged.result_preview == "mail [REDACTED:email]"
    assert err.redactions == ["anthropic_key"] and err.error is not None
    assert err.error.message == "key [REDACTED:anthropic_key]"


def test_literal_secrets_from_config_are_redacted(store: SQLiteAuditStore) -> None:
    logger = AuditLogger(store, Redactor(literal_secrets=["my-custom-db-pass"]))
    event = logger.user_request(logger.new_run_id(), "pw is my-custom-db-pass ok")
    assert event.content == "pw is [REDACTED:secret] ok"


def test_preview_truncated_after_redaction(logger: AuditLogger) -> None:
    # The key straddles the 500-char limit: truncating first would leak its prefix.
    preview = "x" * (MAX_PREVIEW_CHARS - 10) + API_KEY
    event = logger.tool_call(logger.new_run_id(), "t", {"rationale": "r"}, result_preview=preview)
    assert event.result_preview is not None
    assert len(event.result_preview) <= MAX_PREVIEW_CHARS
    assert "sk-ant" not in event.result_preview
    assert event.redactions == ["anthropic_key"]


def test_truncate_helper() -> None:
    assert truncate("abc", 5) == "abc"
    assert truncate("abcdefgh", 5) == "abcd…"


# Timeline


def test_timeline_shows_full_story(logger: AuditLogger, store: SQLiteAuditStore) -> None:
    run = demo_run(logger)
    text = render_timeline(store.get_run_events(run))
    lines = text.splitlines()
    assert f"Run {run}" in text
    step_lines = [line for line in lines if line.startswith("[")]
    assert [line[:4] for line in step_lines] == [f"[{i:02d}]" for i in range(7)]
    assert "call_tool:read_sales_data" in step_lines[1]
    assert "READ data/sample/sales_q1.csv" in step_lines[2]
    assert "XX DENIED" in step_lines[5] and "export_customer_list" in step_lines[5]
    assert "Need the raw Q1 rows first." in text
    assert "60 records; fields: order_id, revenue, customer_email" in text
    assert "PermissionDenied: not in the allowlist" in text
    assert "Outcome:   completed  (1 denied, 0 errors)" in text
    assert "Tokens:    4232 in / 484 out" in text
    assert "Redacted:  email" in text
    assert EMAIL not in text


def test_timeline_marks_failed_run(logger: AuditLogger, store: SQLiteAuditStore) -> None:
    run = logger.new_run_id()
    logger.user_request(run, "go")
    logger.error(run, TimeoutError("model timed out"))
    text = render_timeline(store.get_run_events(run))
    assert "!! ERROR" in text and "TimeoutError: model timed out" in text
    assert "Outcome:   failed  (0 denied, 1 errors)" in text


def test_timeline_wraps_long_text(logger: AuditLogger, store: SQLiteAuditStore) -> None:
    run = logger.new_run_id()
    logger.user_request(run, "word " * 200)
    text = render_timeline(store.get_run_events(run))
    assert max(len(line) for line in text.splitlines()) <= 100
    assert "..." in text  # long content is clipped


def test_timeline_empty() -> None:
    assert render_timeline([]) == "No events for this run."

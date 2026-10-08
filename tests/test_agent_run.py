"""Tests for the AgentRunner loop covering all execution and error paths."""

from pathlib import Path

import pytest
from tests.conftest import FakeModelClient, make_text_response, make_tool_response

from audit_agent.agent.loop import AgentRunner
from audit_agent.audit.events import EventType, Status
from audit_agent.audit.logger import AuditLogger
from audit_agent.storage.sqlite_store import SQLiteAuditStore
from audit_agent.tools.permissions import PermissionGuard
from audit_agent.tools.registry import create_default_registry


@pytest.fixture
def env_setup(tmp_path: Path):
    data_dir = tmp_path / "data"
    output_dir = tmp_path / "output"
    sample_dir = data_dir / "sample"
    sample_dir.mkdir(parents=True)
    output_dir.mkdir(parents=True)

    csv_data = (
        "order_id,date,region,product,units,unit_price,revenue,customer_name,customer_email\n"
        "1001,2026-01-02,North,Widget Pro,10,50.00,500.00,Alice Smith,alice@example.com\n"
        "1002,2026-01-03,South,Gadget Max,5,100.00,500.00,Bob Jones,bob@example.com\n"
    )
    (sample_dir / "sales_q1.csv").write_text(csv_data, encoding="utf-8")

    db_file = tmp_path / "agent_test.db"
    store = SQLiteAuditStore(db_file)
    logger = AuditLogger(store)
    guard = PermissionGuard(data_dir=data_dir, output_dir=output_dir)
    registry = create_default_registry()

    return store, logger, guard, registry, output_dir


def test_agent_happy_path(env_setup) -> None:
    store, logger, guard, registry, output_dir = env_setup

    client = FakeModelClient(
        [
            make_tool_response(
                "read_sales_data",
                {"dataset": "sales_q1", "rationale": "I need to load the Q1 sales records."},
                tool_id="call_1",
                text="I will start by loading the Q1 dataset.",
            ),
            make_tool_response(
                "calculate_stats",
                {
                    "dataset": "sales_q1",
                    "group_by": "region",
                    "rationale": "Calculate regional revenue breakdowns.",
                },
                tool_id="call_2",
                text="Now calculating regional performance.",
            ),
            make_tool_response(
                "write_summary",
                {
                    "filename": "q1_summary.txt",
                    "content": "Q1 Revenue was $1,000 across North and South.",
                    "rationale": "Save the summary report to disk.",
                },
                tool_id="call_3",
                text="Writing summary report to file.",
            ),
            make_text_response("Finished summarizing Q1 sales. Total revenue was $1,000."),
        ]
    )

    runner = AgentRunner(
        model_client=client,
        logger=logger,
        registry=registry,
        guard=guard,
        model="claude-sonnet-4-5",
        max_steps=5,
    )

    result = runner.run("Summarize Q1 sales data")
    assert result.success is True
    assert "Total revenue was $1,000" in result.final_response

    # Verify written summary file
    summary_file = output_dir / "q1_summary.txt"
    assert summary_file.is_file()
    assert "Q1 Revenue was $1,000" in summary_file.read_text(encoding="utf-8")

    # Verify event sequence
    events = store.get_run_events(result.run_id)
    event_types = [e.event_type for e in events]
    assert event_types == [
        EventType.USER_REQUEST,
        EventType.DECISION,
        EventType.DATA_ACCESS,
        EventType.TOOL_CALL,
        EventType.DECISION,
        EventType.DATA_ACCESS,
        EventType.TOOL_CALL,
        EventType.DECISION,
        EventType.DATA_ACCESS,
        EventType.TOOL_CALL,
        EventType.FINAL_RESPONSE,
    ]

    # Verify step_ids are monotonic 0..10
    assert [e.step_id for e in events] == list(range(11))

    # Verify entire chain is valid
    verification = store.verify()
    assert verification.ok is True
    assert verification.events_checked == 11


def test_agent_denied_tool_attempt(env_setup) -> None:
    store, logger, guard, registry, _ = env_setup

    client = FakeModelClient(
        [
            make_tool_response(
                "export_customer_list",
                {"dataset": "sales_q1", "rationale": "Exporting customer PII."},
                tool_id="call_denied",
                text="I will export the customer list.",
            ),
            make_text_response("Export was denied by security policy. Returning summary instead."),
        ]
    )

    runner = AgentRunner(
        model_client=client,
        logger=logger,
        registry=registry,
        guard=guard,
        max_steps=5,
    )

    result = runner.run("Export all customer emails")
    assert result.success is True

    events = store.get_run_events(result.run_id)
    assert [e.event_type for e in events] == [
        EventType.USER_REQUEST,
        EventType.DECISION,
        EventType.TOOL_CALL,
        EventType.FINAL_RESPONSE,
    ]

    denied_call = events[2]
    assert denied_call.status == Status.DENIED
    assert denied_call.tool_name == "export_customer_list"
    assert denied_call.error is not None
    assert denied_call.error.type == "PermissionDenied"

    assert store.verify().ok is True


def test_agent_missing_rationale(env_setup) -> None:
    store, logger, guard, registry, _ = env_setup

    # Tool call without rationale in arguments
    client = FakeModelClient(
        [
            make_tool_response(
                "read_sales_data",
                {"dataset": "sales_q1"},  # Missing rationale
                tool_id="call_no_rat",
                text="Calling without rationale.",
            ),
            make_text_response("Tool failed due to missing rationale."),
        ]
    )

    runner = AgentRunner(
        model_client=client,
        logger=logger,
        registry=registry,
        guard=guard,
        max_steps=5,
    )

    result = runner.run("Read sales")
    assert result.success is True

    events = store.get_run_events(result.run_id)
    assert [e.event_type for e in events] == [
        EventType.USER_REQUEST,
        EventType.DECISION,
        EventType.ERROR,
        EventType.FINAL_RESPONSE,
    ]

    err_event = events[2]
    assert err_event.error.type == "MissingRationale"
    assert store.verify().ok is True


def test_agent_tool_exception(env_setup) -> None:
    store, logger, guard, registry, _ = env_setup

    # Request a non-existent dataset file
    client = FakeModelClient(
        [
            make_tool_response(
                "read_sales_data",
                {"dataset": "nonexistent_file", "rationale": "Try opening missing file."},
                tool_id="call_bad_file",
                text="Reading missing file.",
            ),
            make_text_response("File not found, stopping."),
        ]
    )

    runner = AgentRunner(
        model_client=client,
        logger=logger,
        registry=registry,
        guard=guard,
        max_steps=5,
    )

    result = runner.run("Read bad file")
    assert result.success is True

    events = store.get_run_events(result.run_id)
    assert [e.event_type for e in events] == [
        EventType.USER_REQUEST,
        EventType.DECISION,
        EventType.TOOL_CALL,
        EventType.FINAL_RESPONSE,
    ]

    tool_call_event = events[2]
    assert tool_call_event.status == Status.ERROR
    assert tool_call_event.error.type == "FileNotFoundError"
    assert store.verify().ok is True


def test_agent_max_steps_exceeded(env_setup) -> None:
    store, logger, guard, registry, _ = env_setup

    # Scripted client that loops forever calling tools
    client = FakeModelClient(
        [
            make_tool_response("read_sales_data", {"rationale": "Step 1"}),
            make_tool_response("read_sales_data", {"rationale": "Step 2"}),
            make_tool_response("read_sales_data", {"rationale": "Step 3"}),
        ]
    )

    runner = AgentRunner(
        model_client=client,
        logger=logger,
        registry=registry,
        guard=guard,
        max_steps=2,
    )

    result = runner.run("Infinite loop")
    assert result.success is False
    assert "exceeded maximum step limit" in result.error

    events = store.get_run_events(result.run_id)
    last_event = events[-1]
    assert last_event.event_type == EventType.ERROR
    assert last_event.error.type == "MaxStepsExceeded"
    assert store.verify().ok is True


def test_agent_model_api_error(env_setup) -> None:
    store, logger, guard, registry, _ = env_setup

    class FailingModelClient:
        def generate(self, **kwargs):
            raise ConnectionError("Anthropic API unreachable")

    runner = AgentRunner(
        model_client=FailingModelClient(),
        logger=logger,
        registry=registry,
        guard=guard,
        max_steps=2,
    )

    result = runner.run("Prompt")
    assert result.success is False
    assert "Anthropic API unreachable" in result.error

    events = store.get_run_events(result.run_id)
    assert len(events) == 2
    assert events[0].event_type == EventType.USER_REQUEST
    assert events[1].event_type == EventType.ERROR
    assert events[1].error.type == "ConnectionError"
    assert store.verify().ok is True

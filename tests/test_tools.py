"""Tests for tools, permissions, sandboxing, and registry."""

import json
from pathlib import Path

import pytest

from audit_agent.audit.events import DataOperation, EventType
from audit_agent.audit.logger import AuditLogger
from audit_agent.storage.sqlite_store import SQLiteAuditStore
from audit_agent.tools.base import ToolContext, ToolInputError, validate_args
from audit_agent.tools.permissions import DEFAULT_ALLOWLIST, PermissionDenied, PermissionGuard
from audit_agent.tools.registry import create_default_registry
from audit_agent.tools.restricted import export_customer_list_tool
from audit_agent.tools.sales import read_sales_data_tool
from audit_agent.tools.summary import calculate_stats_tool, write_summary_tool


@pytest.fixture
def workspace_dirs(tmp_path: Path):
    data_dir = tmp_path / "data"
    output_dir = tmp_path / "output"
    sample_dir = data_dir / "sample"
    sample_dir.mkdir(parents=True)
    output_dir.mkdir(parents=True)

    # Copy or create a sample sales CSV
    csv_content = (
        "order_id,date,region,product,units,unit_price,revenue,customer_name,customer_email\n"
        "1001,2026-01-02,North,Widget Pro,10,50.00,500.00,Alice Smith,alice@example.com\n"
        "1002,2026-01-03,South,Gadget Max,5,100.00,500.00,Bob Jones,bob@example.com\n"
        "1003,2026-01-04,North,Gadget Max,2,100.00,200.00,Alice Smith,alice@example.com\n"
    )
    (sample_dir / "sales_q1.csv").write_text(csv_content, encoding="utf-8")

    return data_dir, output_dir


@pytest.fixture
def store(tmp_path: Path):
    with SQLiteAuditStore(tmp_path / "test_audit.db") as s:
        yield s


@pytest.fixture
def logger(store: SQLiteAuditStore):
    return AuditLogger(store)


@pytest.fixture
def guard(workspace_dirs):
    data_dir, output_dir = workspace_dirs
    return PermissionGuard(data_dir=data_dir, output_dir=output_dir)


@pytest.fixture
def tool_context(logger: AuditLogger, guard: PermissionGuard):
    run_id = logger.new_run_id()
    logger.user_request(run_id, "Test prompt")
    return ToolContext(
        run_id=run_id,
        tool_name="test_tool",
        logger=logger,
        guard=guard,
    )


# Rationale injection & schemas


def test_tool_anthropic_schema_injects_required_rationale() -> None:
    schema = read_sales_data_tool.anthropic_schema()
    assert schema["name"] == "read_sales_data"
    input_schema = schema["input_schema"]
    assert "rationale" in input_schema["properties"]
    assert "rationale" in input_schema["required"]
    assert input_schema["properties"]["rationale"]["type"] == "string"


def test_prepare_args_removes_rationale_and_applies_defaults() -> None:
    raw = {"rationale": "I need to look up sales numbers."}
    cleaned = read_sales_data_tool.prepare_args(raw)
    assert "rationale" not in cleaned
    assert cleaned["dataset"] == "sample/sales_q1.csv"


def test_validate_args_errors() -> None:
    schema = {
        "type": "object",
        "properties": {
            "name": {"type": "string", "minLength": 2},
            "count": {"type": "integer", "minimum": 1, "maximum": 10},
            "kind": {"type": "string", "enum": ["a", "b"]},
        },
        "required": ["name"],
        "additionalProperties": False,
    }

    with pytest.raises(ToolInputError, match="Missing required"):
        validate_args(schema, {})

    with pytest.raises(ToolInputError, match="Unknown argument"):
        validate_args(schema, {"name": "ok", "extra": 123})

    with pytest.raises(ToolInputError, match="type integer"):
        validate_args(schema, {"name": "ok", "count": "five"})

    with pytest.raises(ToolInputError, match=">= 1"):
        validate_args(schema, {"name": "ok", "count": 0})

    with pytest.raises(ToolInputError, match="<= 10"):
        validate_args(schema, {"name": "ok", "count": 11})

    with pytest.raises(ToolInputError, match="one of"):
        validate_args(schema, {"name": "ok", "kind": "c"})


# PermissionGuard & Sandbox


def test_permission_guard_allowlist(guard: PermissionGuard) -> None:
    for name in DEFAULT_ALLOWLIST:
        verdict = guard.check_tool(name)
        assert verdict.allowed is True

    verdict = guard.check_tool("export_customer_list")
    assert verdict.allowed is False
    assert "not in the allowlist" in verdict.reason


def test_permission_guard_sandbox_reads(guard: PermissionGuard, workspace_dirs) -> None:
    data_dir, _ = workspace_dirs
    resolved = guard.resolve_read("sample/sales_q1.csv")
    assert resolved == (data_dir / "sample" / "sales_q1.csv").resolve()

    with pytest.raises(PermissionDenied, match="outside the allowed read"):
        guard.resolve_read("../../secret.txt")

    with pytest.raises(PermissionDenied, match="outside the allowed read"):
        guard.resolve_read("C:/Windows/System32/calc.exe")

    with pytest.raises(PermissionDenied, match="Empty path"):
        guard.resolve_read("")


def test_permission_guard_sandbox_writes(guard: PermissionGuard, workspace_dirs) -> None:
    _, output_dir = workspace_dirs
    resolved = guard.resolve_write("sub/summary.txt")
    assert resolved == (output_dir / "sub" / "summary.txt").resolve()

    with pytest.raises(PermissionDenied, match="outside the allowed write"):
        guard.resolve_write("../escaped.txt")


# Standalone tool execution & DataAccess logging


def test_read_sales_data_tool(tool_context: ToolContext, store: SQLiteAuditStore) -> None:
    ctx = ToolContext(
        run_id=tool_context.run_id,
        tool_name=read_sales_data_tool.name,
        logger=tool_context.logger,
        guard=tool_context.guard,
    )
    raw_res = read_sales_data_tool.func(ctx, {"dataset": "sales_q1"})
    data = json.loads(raw_res)
    assert data["total_records"] == 3
    assert len(data["rows"]) == 3
    assert data["dataset"] == "data/sample/sales_q1.csv"

    # Verify filtering
    raw_north = read_sales_data_tool.func(ctx, {"dataset": "sales_q1", "region": "North"})
    data_north = json.loads(raw_north)
    assert data_north["returned_records"] == 2

    # Check data_access events
    events = store.get_run_events(tool_context.run_id, event_type=EventType.DATA_ACCESS)
    assert len(events) == 2
    assert events[0].data_source == "data/sample/sales_q1.csv"
    assert events[0].data_operation == DataOperation.READ
    assert events[0].records_touched == 3
    assert "customer_email" in events[0].fields_accessed


def test_calculate_stats_tool(tool_context: ToolContext, store: SQLiteAuditStore) -> None:
    ctx = ToolContext(
        run_id=tool_context.run_id,
        tool_name=calculate_stats_tool.name,
        logger=tool_context.logger,
        guard=tool_context.guard,
    )
    res_str = calculate_stats_tool.func(ctx, {"dataset": "sample/sales_q1.csv"})
    stats = json.loads(res_str)
    assert stats["total_orders"] == 3
    assert stats["total_revenue"] == 1200.00
    assert stats["total_units_sold"] == 17
    assert stats["revenue_by_region"]["North"] == 700.00
    assert stats["revenue_by_region"]["South"] == 500.00

    # Group by region
    res_grouped = calculate_stats_tool.func(
        ctx, {"dataset": "sample/sales_q1.csv", "group_by": "region"}
    )
    grouped = json.loads(res_grouped)
    assert "by_region" in grouped
    assert grouped["by_region"]["North"]["orders"] == 2

    events = store.get_run_events(tool_context.run_id, event_type=EventType.DATA_ACCESS)
    assert len(events) == 2


def test_write_summary_tool(
    tool_context: ToolContext, workspace_dirs, store: SQLiteAuditStore
) -> None:
    _, output_dir = workspace_dirs
    ctx = ToolContext(
        run_id=tool_context.run_id,
        tool_name=write_summary_tool.name,
        logger=tool_context.logger,
        guard=tool_context.guard,
    )
    result = write_summary_tool.func(
        ctx,
        {"filename": "q1_report.txt", "content": "Q1 Revenue was $1,200.00 with 17 units sold."},
    )
    assert "Successfully wrote summary to output/q1_report.txt" in result

    written_file = output_dir / "q1_report.txt"
    assert written_file.is_file()
    assert (
        written_file.read_text(encoding="utf-8") == "Q1 Revenue was $1,200.00 with 17 units sold."
    )

    events = store.get_run_events(tool_context.run_id, event_type=EventType.DATA_ACCESS)
    assert len(events) == 1
    assert events[0].data_operation == DataOperation.WRITE
    assert events[0].data_source == "output/q1_report.txt"


def test_export_customer_list_tool(
    tool_context: ToolContext, workspace_dirs, store: SQLiteAuditStore
) -> None:
    _, output_dir = workspace_dirs
    ctx = ToolContext(
        run_id=tool_context.run_id,
        tool_name=export_customer_list_tool.name,
        logger=tool_context.logger,
        guard=tool_context.guard,
    )
    res = export_customer_list_tool.func(
        ctx, {"dataset": "sample/sales_q1.csv", "filename": "customers.csv"}
    )
    assert "Exported 2 unique customers" in res

    out_file = output_dir / "customers.csv"
    assert out_file.is_file()
    lines = out_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3  # header + 2 unique customers

    events = store.get_run_events(tool_context.run_id, event_type=EventType.DATA_ACCESS)
    assert len(events) == 2  # 1 read, 1 write


# ToolRegistry


def test_tool_registry() -> None:
    registry = create_default_registry()
    assert len(registry.list_tools()) == 4
    assert "read_sales_data" in registry
    assert "export_customer_list" in registry
    assert registry.get("nonexistent") is None

    schemas = registry.anthropic_schemas()
    assert len(schemas) == 4
    for schema in schemas:
        assert "name" in schema
        assert "rationale" in schema["input_schema"]["properties"]

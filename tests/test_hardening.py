"""Hardening and edge-case tests: empty CSV, huge payload, unicode, and concurrent appends."""

import concurrent.futures
import uuid
from pathlib import Path

import pytest

from audit_agent.audit.events import (
    MAX_PREVIEW_CHARS,
    Actor,
    AuditEventBody,
    EventType,
)
from audit_agent.audit.logger import AuditLogger
from audit_agent.storage.sqlite_store import SQLiteAuditStore
from audit_agent.tools.base import ToolContext
from audit_agent.tools.permissions import PermissionGuard
from audit_agent.tools.sales import read_sales_data_tool
from audit_agent.tools.summary import calculate_stats_tool


@pytest.fixture
def test_dirs(tmp_path: Path):
    data_dir = tmp_path / "data"
    output_dir = tmp_path / "output"
    data_dir.mkdir(parents=True)
    output_dir.mkdir(parents=True)
    return data_dir, output_dir


def test_empty_csv_handling(test_dirs, tmp_path: Path) -> None:
    """Tools handle CSVs with headers but 0 rows gracefully."""
    data_dir, output_dir = test_dirs
    empty_csv = data_dir / "empty.csv"
    empty_csv.write_text(
        "order_id,date,region,product,units,unit_price,revenue,customer_name,customer_email\n",
        encoding="utf-8",
    )

    db_path = tmp_path / "hardening.db"
    with SQLiteAuditStore(db_path) as store:
        logger = AuditLogger(store)
        guard = PermissionGuard(data_dir=data_dir, output_dir=output_dir)
        run_id = logger.new_run_id()

        ctx = ToolContext(run_id=run_id, tool_name="read_sales_data", logger=logger, guard=guard)
        res_read = read_sales_data_tool.func(ctx, {"dataset": "empty.csv"})
        assert '"total_records": 0' in res_read

        ctx_stats = ToolContext(
            run_id=run_id, tool_name="calculate_stats", logger=logger, guard=guard
        )
        res_stats = calculate_stats_tool.func(ctx_stats, {"dataset": "empty.csv"})
        assert '"total_orders": 0' in res_stats

        events = store.get_run_events(run_id, event_type=EventType.DATA_ACCESS)
        assert len(events) == 2
        assert events[0].records_touched == 0
        assert events[1].records_touched == 0
        assert store.verify().ok is True


def test_huge_args_and_preview_truncation(tmp_path: Path) -> None:
    """Enormous payloads and previews are properly handled, redacted, and truncated."""
    db_path = tmp_path / "huge.db"
    with SQLiteAuditStore(db_path) as store:
        logger = AuditLogger(store)
        run_id = logger.new_run_id()

        huge_text = "A" * 50_000
        logger.user_request(run_id, "Process large input")

        huge_preview = "Data block: " + ("x" * 2000)
        tc_event = logger.tool_call(
            run_id,
            "read_sales_data",
            tool_args={"payload": huge_text},
            rationale="Handle large payload",
            result_preview=huge_preview,
        )

        assert tc_event.result_preview is not None
        assert len(tc_event.result_preview) <= MAX_PREVIEW_CHARS
        assert tc_event.result_preview.endswith("…")

        assert store.verify().ok is True


def test_unicode_and_special_characters(tmp_path: Path) -> None:
    """Unicode, emojis, and multilingual text preserve exact integrity through hash chain."""
    db_path = tmp_path / "unicode.db"
    with SQLiteAuditStore(db_path) as store:
        logger = AuditLogger(store)
        run_id = logger.new_run_id()

        multilingual = (
            "Hello 🌍! नमस्ते, 你好, こんにちは, Привет! "
            "Accents: é à ö ü ñ ç ø. Math: ∑ ∫ √ π. Symbols: 🔒 ⚡ 🛡️."
        )

        logger.user_request(run_id, multilingual)
        logger.decision(run_id, "final_answer", rationale="Processed multilingual query.")
        logger.final_response(run_id, multilingual)

        events = store.get_run_events(run_id)
        assert events[0].content == multilingual
        assert events[2].content == multilingual

        verification = store.verify()
        assert verification.ok is True
        assert verification.events_checked == 3


def test_concurrent_appends(tmp_path: Path) -> None:
    """Concurrent writers appending events simultaneously preserve chain integrity."""
    db_path = tmp_path / "concurrent.db"

    # Pre-initialize database schema
    SQLiteAuditStore(db_path).close()

    total_threads = 6
    events_per_thread = 15
    total_events = total_threads * events_per_thread

    def worker(worker_id: int) -> list[int]:
        assigned_seqs = []
        with SQLiteAuditStore(db_path, timeout_s=30.0) as store:
            run_id = str(uuid.uuid4())
            for step in range(events_per_thread):
                body = AuditEventBody(
                    run_id=run_id,
                    step_id=step,
                    event_type=EventType.DECISION,
                    actor=Actor.AGENT,
                    decision=f"worker_{worker_id}_step_{step}",
                )
                event = store.append(body)
                assigned_seqs.append(event.seq)
        return assigned_seqs

    with concurrent.futures.ThreadPoolExecutor(max_workers=total_threads) as executor:
        futures = [executor.submit(worker, i) for i in range(total_threads)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    all_seqs = [seq for res in results for seq in res]
    assert len(all_seqs) == total_events
    assert sorted(all_seqs) == list(range(1, total_events + 1))

    with SQLiteAuditStore(db_path) as store:
        assert store.count() == total_events
        verification = store.verify()
        assert verification.ok is True
        assert verification.events_checked == total_events

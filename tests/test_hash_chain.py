"""Tests for audit/hashchain.py and storage/sqlite_store.py.

Tamper tests act as an attacker with raw DB access. Some drop the append-only triggers
first, which production code must never do, to show that verification still catches it.
"""

import hashlib
import json
import sqlite3
import uuid
from pathlib import Path
from typing import Any

import pytest

from audit_agent.audit.events import (
    GENESIS_HASH,
    Actor,
    AuditEvent,
    AuditEventBody,
    DataOperation,
    EventType,
)
from audit_agent.audit.hashchain import (
    TamperedRecordError,
    canonical_json,
    chain_event,
    compute_hash,
    event_hash,
    verify_chain,
)
from audit_agent.storage.sqlite_store import SQLiteAuditStore

# Helpers


def body(run_id: str, step_id: int, event_type: EventType = EventType.DECISION) -> AuditEventBody:
    fields: dict[str, Any] = {
        EventType.USER_REQUEST: {"actor": Actor.USER, "content": "Summarize Q1 sales — ünïcødé ✓"},
        EventType.DECISION: {"actor": Actor.AGENT, "decision": "call_tool:read_sales_data"},
        EventType.DATA_ACCESS: {
            "actor": Actor.TOOL,
            "tool_name": "read_sales_data",
            "data_source": "data/sample/sales_q1.csv",
            "data_operation": DataOperation.READ,
            "records_touched": 60,
            "fields_accessed": ["order_id", "revenue"],
        },
        EventType.FINAL_RESPONSE: {"actor": Actor.AGENT, "content": "Q1 revenue was $482,310."},
    }[event_type]
    return AuditEventBody(run_id=run_id, step_id=step_id, event_type=event_type, **fields)


def build_chain(n: int) -> list[AuditEvent]:
    run_id = str(uuid.uuid4())
    events: list[AuditEvent] = []
    prev = GENESIS_HASH
    for i in range(n):
        event = chain_event(body(run_id, i), seq=i + 1, prev_hash=prev)
        events.append(event)
        prev = event.hash
    return events


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "nested" / "audit.db"


@pytest.fixture
def store(db_path: Path):
    with SQLiteAuditStore(db_path) as s:
        yield s


def fill(store: SQLiteAuditStore, runs: int = 2, steps: int = 3) -> list[str]:
    run_ids = []
    for _ in range(runs):
        run_id = str(uuid.uuid4())
        run_ids.append(run_id)
        store.append(body(run_id, 0, EventType.USER_REQUEST))
        for step in range(1, steps - 1):
            store.append(body(run_id, step, EventType.DATA_ACCESS))
        store.append(body(run_id, steps - 1, EventType.FINAL_RESPONSE))
    return run_ids


def raw(db_path: Path, *, drop_triggers: bool = False) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, isolation_level=None)
    if drop_triggers:
        conn.execute("DROP TRIGGER audit_no_update")
        conn.execute("DROP TRIGGER audit_no_delete")
    return conn


# Canonical JSON & hashing


def test_canonical_json_is_sorted_compact_utf8() -> None:
    assert canonical_json({"b": 1, "a": [1, {"d": 2, "c": "é"}]}) == (
        '{"a":[1,{"c":"é","d":2}],"b":1}'.encode()
    )


def test_canonical_json_rejects_nan() -> None:
    with pytest.raises(ValueError):
        canonical_json({"x": float("nan")})


def test_compute_hash_is_sha256_of_payload_without_hash_field() -> None:
    payload = {"seq": 1, "content": "x"}
    expected = hashlib.sha256(b'{"content":"x","seq":1}').hexdigest()
    assert compute_hash(payload) == expected
    assert compute_hash(payload | {"hash": "anything"}) == expected


def test_chain_event_sets_chain_fields_and_valid_hash() -> None:
    event = chain_event(body(str(uuid.uuid4()), 0), seq=1, prev_hash=GENESIS_HASH)
    assert (event.seq, event.prev_hash) == (1, GENESIS_HASH)
    assert event.hash == event_hash(event)


@pytest.mark.parametrize(
    "field,value",
    [("content", "changed"), ("step_id", 7), ("seq", 2), ("prev_hash", "f" * 64)],
)
def test_hash_covers_content_and_chain_fields(field: str, value: Any) -> None:
    event = build_chain(1)[0]
    assert event_hash(event.model_copy(update={field: value})) != event.hash


# verify_chain on in-memory chains


def test_verify_valid_and_empty_chain() -> None:
    events = build_chain(5)
    result = verify_chain(events)
    assert result.ok and result.events_checked == 5 and result.head_hash == events[-1].hash
    empty = verify_chain([])
    assert empty.ok and empty.events_checked == 0 and empty.head_hash == GENESIS_HASH


def test_verify_detects_edit() -> None:
    events = build_chain(5)
    events[2] = events[2].model_copy(update={"decision": "final_answer"})
    result = verify_chain(events)
    assert not result.ok and result.problem is not None
    assert result.problem.seq == 3 and "hash mismatch" in result.problem.reason
    assert result.events_checked == 2


@pytest.mark.parametrize("index", [0, 2, 4])
def test_verify_detects_deletion(index: int) -> None:
    events = build_chain(5)
    del events[index]
    result = verify_chain(events)
    if index == 4:  # tail truncation is a documented limitation of chain-only checks
        assert result.ok
    else:
        assert not result.ok and result.problem is not None and result.problem.seq == index + 2


def test_verify_detects_reorder() -> None:
    events = build_chain(5)
    events[1], events[2] = events[2], events[1]
    result = verify_chain(events)
    assert not result.ok and result.problem is not None and result.problem.seq == 3


def test_verify_detects_insert_even_with_self_consistent_hash() -> None:
    events = build_chain(4)
    forged = chain_event(body(events[0].run_id, 9), seq=3, prev_hash=events[1].hash)
    events.insert(2, forged)  # forged is internally valid, but breaks the next link
    result = verify_chain(events)
    assert not result.ok and result.problem is not None
    assert result.problem.seq == 3 and "expected seq 4" in result.problem.reason


def test_verify_reports_tampered_record_error_from_iterator() -> None:
    def rows():
        yield from build_chain(2)
        raise TamperedRecordError(3, "payload is not a valid event")

    result = verify_chain(rows())
    assert not result.ok and result.events_checked == 2
    assert result.problem is not None and result.problem.seq == 3


# Store: appends and reads


def test_append_builds_global_chain_across_runs(store: SQLiteAuditStore) -> None:
    fill(store, runs=2, steps=3)
    events = list(store.iter_all())
    assert [e.seq for e in events] == [1, 2, 3, 4, 5, 6]
    assert events[0].prev_hash == GENESIS_HASH
    assert all(b.prev_hash == a.hash for a, b in zip(events, events[1:], strict=False))
    assert len({e.run_id for e in events}) == 2
    assert store.verify().ok and store.count() == 6


def test_append_returns_the_persisted_event(store: SQLiteAuditStore) -> None:
    run_id = str(uuid.uuid4())
    returned = store.append(body(run_id, 0, EventType.USER_REQUEST))
    assert store.get_run_events(run_id) == [returned]
    assert returned.content == "Summarize Q1 sales — ünïcødé ✓"


def test_payload_is_canonical_json_of_event(store: SQLiteAuditStore, db_path: Path) -> None:
    event = store.append(body(str(uuid.uuid4()), 0))
    (payload,) = raw(db_path).execute("SELECT payload FROM audit_events").fetchone()
    assert payload.encode() == canonical_json(event.model_dump(mode="json"))
    assert json.loads(payload)["hash"] == event.hash


def test_get_run_events_orders_and_filters(store: SQLiteAuditStore) -> None:
    run_a, run_b = fill(store, runs=2, steps=4)
    events = store.get_run_events(run_a)
    assert [e.step_id for e in events] == [0, 1, 2, 3]
    assert {e.run_id for e in events} == {run_a}
    access = store.get_run_events(run_b, EventType.DATA_ACCESS)
    assert [e.step_id for e in access] == [1, 2]
    assert store.get_run_events(str(uuid.uuid4())) == []


def test_list_runs_most_recent_first(store: SQLiteAuditStore) -> None:
    run_a, run_b = fill(store, runs=2, steps=3)
    runs = store.list_runs()
    assert [r.run_id for r in runs] == [run_b, run_a]
    assert runs[0].event_count == 3 and (runs[0].first_seq, runs[0].last_seq) == (4, 6)
    assert runs[0].non_ok_events == 0
    assert [r.run_id for r in store.list_runs(limit=1)] == [run_b]


def test_reopen_continues_chain(db_path: Path) -> None:
    with SQLiteAuditStore(db_path) as s:
        first = s.append(body(str(uuid.uuid4()), 0))
    with SQLiteAuditStore(db_path) as s:
        second = s.append(body(str(uuid.uuid4()), 0))
        assert (second.seq, second.prev_hash) == (2, first.hash)
        assert s.verify().ok


def test_failed_append_rolls_back_and_chain_stays_valid(store: SQLiteAuditStore) -> None:
    first = store.append(body(str(uuid.uuid4()), 0))
    duplicate = body(first.run_id, 1).model_copy(update={"event_id": first.event_id})
    with pytest.raises(sqlite3.IntegrityError):
        store.append(duplicate)
    second = store.append(body(first.run_id, 1))
    assert (second.seq, second.prev_hash) == (2, first.hash)
    assert store.verify().ok


def test_store_exposes_no_update_or_delete_api(store: SQLiteAuditStore) -> None:
    public = [name for name in dir(store) if not name.startswith("_")]
    assert not [n for n in public if any(w in n for w in ("update", "delete", "remove"))]


# Store: append-only triggers


def test_update_blocked_by_trigger(store: SQLiteAuditStore, db_path: Path) -> None:
    fill(store, runs=1)
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        raw(db_path).execute("UPDATE audit_events SET status = 'error' WHERE seq = 1")


def test_delete_blocked_by_trigger(store: SQLiteAuditStore, db_path: Path) -> None:
    fill(store, runs=1)
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        raw(db_path).execute("DELETE FROM audit_events WHERE seq = 1")
    assert store.count() == 3


def test_reopening_does_not_duplicate_or_remove_triggers(db_path: Path) -> None:
    SQLiteAuditStore(db_path).close()
    with SQLiteAuditStore(db_path):
        names = raw(db_path).execute("SELECT name FROM sqlite_master WHERE type='trigger'")
        assert sorted(n for (n,) in names) == ["audit_no_delete", "audit_no_update"]


# Store: tampering with triggers bypassed


def tamper(db_path: Path, sql: str, *params: Any) -> None:
    conn = raw(db_path, drop_triggers=True)
    conn.execute(sql, params)
    conn.close()


def test_verify_detects_payload_edit_in_db(store: SQLiteAuditStore, db_path: Path) -> None:
    fill(store)
    (payload,) = raw(db_path).execute("SELECT payload FROM audit_events WHERE seq=3").fetchone()
    edited = json.loads(payload) | {"content": "Q1 revenue was $1."}
    tamper(db_path, "UPDATE audit_events SET payload=? WHERE seq=3", json.dumps(edited))
    result = store.verify()
    assert not result.ok and result.problem is not None
    assert result.problem.seq == 3 and "hash mismatch" in result.problem.reason


def test_verify_detects_indexed_column_edit(store: SQLiteAuditStore, db_path: Path) -> None:
    fill(store)
    tamper(db_path, "UPDATE audit_events SET status='denied' WHERE seq=2")
    result = store.verify()
    assert not result.ok and result.problem is not None
    assert result.problem.seq == 2 and "status" in result.problem.reason


def test_verify_detects_corrupt_payload(store: SQLiteAuditStore, db_path: Path) -> None:
    fill(store)
    tamper(db_path, "UPDATE audit_events SET payload='{not json' WHERE seq=4")
    result = store.verify()
    assert not result.ok and result.problem is not None and result.problem.seq == 4


def test_verify_detects_row_deletion_in_db(store: SQLiteAuditStore, db_path: Path) -> None:
    fill(store)
    tamper(db_path, "DELETE FROM audit_events WHERE seq=2")
    result = store.verify()
    assert not result.ok and result.problem is not None
    assert result.problem.seq == 3 and "expected seq 2" in result.problem.reason


def test_verify_detects_whole_run_deletion(store: SQLiteAuditStore, db_path: Path) -> None:
    run_a, _ = fill(store, runs=2)
    tamper(db_path, "DELETE FROM audit_events WHERE run_id=?", run_a)
    assert not store.verify().ok


def test_verify_detects_reorder_in_db(store: SQLiteAuditStore, db_path: Path) -> None:
    fill(store)
    conn = raw(db_path, drop_triggers=True)
    conn.execute("UPDATE audit_events SET seq = -2 WHERE seq = 2")
    conn.execute("UPDATE audit_events SET seq = 2 WHERE seq = 3")
    conn.execute("UPDATE audit_events SET seq = 3 WHERE seq = -2")
    conn.close()
    result = store.verify()
    assert not result.ok and result.problem is not None and result.problem.seq == 2


def test_verify_detects_inserted_row(store: SQLiteAuditStore, db_path: Path) -> None:
    fill(store, runs=1)  # seq 1..3
    events = list(store.iter_all())
    # Attacker shifts seq 3 out of the way and inserts a forged, self-consistent event.
    forged = chain_event(body(events[0].run_id, 5), seq=3, prev_hash=events[1].hash)
    payload = forged.model_dump(mode="json")
    conn = raw(db_path, drop_triggers=True)
    conn.execute("UPDATE audit_events SET seq = 4 WHERE seq = 3")
    cols = ["seq", "event_id", "run_id", "step_id", "timestamp", "event_type", "status",
            "tool_name", "prev_hash", "hash"]  # fmt: skip
    conn.execute(
        f"INSERT INTO audit_events ({', '.join(cols)}, payload) VALUES ({', '.join('?' * 11)})",
        [payload[c] for c in cols] + [canonical_json(payload).decode()],
    )
    conn.close()
    result = store.verify()
    assert not result.ok and result.problem is not None
    assert result.problem.seq == 4  # moved row: its payload seq/prev_hash no longer match

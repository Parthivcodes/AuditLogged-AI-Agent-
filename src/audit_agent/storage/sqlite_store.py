"""Append-only SQLite storage for audit events.

The ``audit_events`` table is guarded by triggers that abort any UPDATE or DELETE.
This module exposes no update/delete paths. ``append`` takes an already-redacted
``AuditEventBody``. Callers must go through ``AuditLogger``, which redacts first.

Each append runs in a ``BEGIN IMMEDIATE`` transaction: it takes the write lock, reads
the chain head, assigns the next ``seq``, computes the hash, and inserts. So two writers
can never chain onto the same head.

Rows store the full canonical JSON event in ``payload``. The other columns are indexed
copies for querying. Readers rebuild events from ``payload`` and raise
``TamperedRecordError`` if the copies disagree with it.
"""

import json
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from types import TracebackType
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, ValidationError

from audit_agent.audit.events import GENESIS_HASH, AuditEvent, AuditEventBody, EventType
from audit_agent.audit.hashchain import (
    TamperedRecordError,
    VerificationResult,
    canonical_json,
    chain_event,
    event_payload,
    verify_chain,
)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS audit_events (
  seq INTEGER PRIMARY KEY, event_id TEXT UNIQUE NOT NULL, run_id TEXT NOT NULL,
  step_id INTEGER NOT NULL, timestamp TEXT NOT NULL, event_type TEXT NOT NULL,
  status TEXT NOT NULL, tool_name TEXT, payload TEXT NOT NULL,
  prev_hash TEXT NOT NULL, hash TEXT UNIQUE NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_audit_run ON audit_events(run_id, step_id);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_events
  BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_events
  BEGIN SELECT RAISE(ABORT, 'append-only'); END;
"""

# Columns duplicated from the payload; readers check they still agree.
_INDEXED_COLUMNS = (
    "seq", "event_id", "run_id", "step_id", "timestamp",
    "event_type", "status", "tool_name", "prev_hash", "hash",
)  # fmt: skip
_SELECT = f"SELECT {', '.join(_INDEXED_COLUMNS)}, payload FROM audit_events"
_INSERT = (
    f"INSERT INTO audit_events ({', '.join(_INDEXED_COLUMNS)}, payload) "
    f"VALUES ({', '.join('?' * (len(_INDEXED_COLUMNS) + 1))})"
)


class RunSummary(BaseModel):
    """One row of ``list_runs``."""

    model_config = ConfigDict(frozen=True)

    run_id: str
    started_at: str
    ended_at: str
    event_count: int
    first_seq: int
    last_seq: int
    non_ok_events: int


class SQLiteAuditStore:
    """Append-only, hash-chained audit event store backed by one SQLite file."""

    def __init__(self, path: str | Path, *, timeout_s: float = 10.0) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # isolation_level=None: no implicit transactions; we issue BEGIN IMMEDIATE ourselves.
        self._conn = sqlite3.connect(self.path, timeout=timeout_s, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA_SQL)

    # Lifecycle

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    # Writes

    def append(self, body: AuditEventBody) -> AuditEvent:
        """Chain ``body`` onto the current head and insert it atomically.

        ``body`` must already be redacted. Returns the persisted event.
        """
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            head = self._conn.execute(
                "SELECT seq, hash FROM audit_events ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            seq, prev_hash = (head["seq"] + 1, head["hash"]) if head else (1, GENESIS_HASH)
            event = chain_event(body, seq=seq, prev_hash=prev_hash)
            payload = event_payload(event)
            row = [payload[col] for col in _INDEXED_COLUMNS]
            self._conn.execute(_INSERT, [*row, canonical_json(payload).decode("utf-8")])
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        self._conn.execute("COMMIT")
        return event

    # Reads

    def iter_all(self) -> Iterator[AuditEvent]:
        """Every event in ``seq`` order, streamed. Raises ``TamperedRecordError``."""
        for row in self._conn.execute(f"{_SELECT} ORDER BY seq"):
            yield _row_to_event(row)

    def get_run_events(self, run_id: str, event_type: EventType | None = None) -> list[AuditEvent]:
        """Events of one run in step order, optionally filtered by type."""
        sql, params = f"{_SELECT} WHERE run_id = ?", [run_id]
        if event_type is not None:
            sql += " AND event_type = ?"
            params.append(EventType(event_type).value)
        rows = self._conn.execute(f"{sql} ORDER BY step_id, seq", params)
        return [_row_to_event(row) for row in rows]

    def list_runs(self, limit: int | None = None) -> list[RunSummary]:
        """Run summaries, most recent first."""
        sql = """
            SELECT run_id, MIN(timestamp) AS started_at, MAX(timestamp) AS ended_at,
                   COUNT(*) AS event_count, MIN(seq) AS first_seq, MAX(seq) AS last_seq,
                   SUM(status != 'ok') AS non_ok_events
            FROM audit_events GROUP BY run_id ORDER BY MAX(seq) DESC
        """
        params: list[Any] = []
        if limit is not None:
            sql += " LIMIT ?"
            params.append(limit)
        return [RunSummary(**dict(row)) for row in self._conn.execute(sql, params)]

    def count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]

    def last_step_id(self, run_id: str) -> int | None:
        """Highest ``step_id`` logged for ``run_id``, or ``None`` for a new run."""
        sql = "SELECT MAX(step_id) FROM audit_events WHERE run_id = ?"
        return self._conn.execute(sql, [run_id]).fetchone()[0]

    def verify(self) -> VerificationResult:
        """Recompute and check the whole global chain."""
        return verify_chain(self.iter_all())


def _row_to_event(row: sqlite3.Row) -> AuditEvent:
    seq = row["seq"]
    try:
        payload = json.loads(row["payload"])
        event = AuditEvent.model_validate(payload)
    except (ValueError, ValidationError) as exc:  # JSONDecodeError is a ValueError
        raise TamperedRecordError(seq, f"payload is not a valid event: {exc}") from exc
    stored = event_payload(event)
    mismatched = [col for col in _INDEXED_COLUMNS if row[col] != stored[col]]
    if mismatched:
        raise TamperedRecordError(seq, f"columns disagree with payload: {', '.join(mismatched)}")
    return event

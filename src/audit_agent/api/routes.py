"""Read-only FastAPI endpoints for querying runs, events, and verifying hash chains."""

from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict

from audit_agent.audit.events import AuditEvent, EventType
from audit_agent.audit.hashchain import VerificationResult
from audit_agent.config import Settings
from audit_agent.storage.sqlite_store import RunSummary, SQLiteAuditStore

router = APIRouter()


def get_db_store(request: Request) -> SQLiteAuditStore:
    """Dependency that yields a SQLiteAuditStore connected to the configured database."""
    # Check if a custom db_path was set on app.state (e.g. in tests)
    db_path = getattr(request.app.state, "db_path", None)
    if not db_path:
        db_path = Settings.from_env().db_path
    return SQLiteAuditStore(Path(db_path))


class HealthResponse(BaseModel):
    model_config = ConfigDict(frozen=True)
    status: str
    version: str


class ProblemDetail(BaseModel):
    model_config = ConfigDict(frozen=True)
    seq: int | None
    reason: str


class VerifyResponse(BaseModel):
    model_config = ConfigDict(frozen=True)
    ok: bool
    events_checked: int
    head_hash: str
    problem: ProblemDetail | None = None


@router.get("/health", response_model=HealthResponse)
def get_health() -> HealthResponse:
    """Healthcheck endpoint."""
    return HealthResponse(status="ok", version="0.1.0")


@router.get("/runs", response_model=list[RunSummary])
def list_runs(
    store: Annotated[SQLiteAuditStore, Depends(get_db_store)],
    limit: Annotated[int, Query(ge=1, le=1000)] = 50,
) -> list[RunSummary]:
    """List recent agent runs in reverse chronological order."""
    with store:
        return store.list_runs(limit=limit)


@router.get("/runs/{run_id}", response_model=RunSummary)
def get_run(
    run_id: str,
    store: Annotated[SQLiteAuditStore, Depends(get_db_store)],
) -> RunSummary:
    """Get metadata summary for a single run."""
    with store:
        runs = store.list_runs()
        for r in runs:
            if r.run_id == run_id:
                return r
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Run '{run_id}' not found",
        )


@router.get("/runs/{run_id}/events", response_model=list[AuditEvent])
def get_run_events(
    run_id: str,
    store: Annotated[SQLiteAuditStore, Depends(get_db_store)],
    event_type: Annotated[EventType | None, Query()] = None,
) -> list[AuditEvent]:
    """Get all audit events for a run in chronological order, optionally filtered by event_type."""
    with store:
        events = store.get_run_events(run_id, event_type=event_type)
        if not events:
            # Check if run exists at all if empty
            all_events = store.get_run_events(run_id)
            if not all_events:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Run '{run_id}' not found",
                )
        return events


@router.get("/verify", response_model=VerifyResponse)
def verify_audit_chain(
    store: Annotated[SQLiteAuditStore, Depends(get_db_store)],
) -> VerifyResponse:
    """Verify cryptographic SHA-256 hash chain integrity across all events and runs."""
    with store:
        res: VerificationResult = store.verify()
        prob = None
        if res.problem:
            prob = ProblemDetail(seq=res.problem.seq, reason=res.problem.reason)
        return VerifyResponse(
            ok=res.ok,
            events_checked=res.events_checked,
            head_hash=res.head_hash,
            problem=prob,
        )

"""Tests for the read-only FastAPI service."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from audit_agent.api.app import create_app
from audit_agent.audit.events import EventType
from audit_agent.audit.logger import AuditLogger
from audit_agent.storage.sqlite_store import SQLiteAuditStore


@pytest.fixture
def populated_db(tmp_path: Path):
    db_file = tmp_path / "api_test.db"
    with SQLiteAuditStore(db_file) as store:
        logger = AuditLogger(store)

        # Run 1: Complete 3-step run
        run_1 = logger.new_run_id()
        logger.user_request(run_1, "Analyze Q1 sales")
        logger.tool_call(
            run_1,
            "read_sales_data",
            {"dataset": "sales_q1"},
            rationale="Need to load raw sales data.",
            result_preview="Loaded 60 rows.",
        )
        logger.final_response(run_1, "Sales analysis complete.")

        # Run 2: Error run
        run_2 = logger.new_run_id()
        logger.user_request(run_2, "Failed prompt")
        logger.error(run_2, RuntimeError("Simulated failure"))

    return db_file, run_1, run_2


@pytest.fixture
def client(populated_db: tuple[Path, str, str]) -> TestClient:
    db_file, _, _ = populated_db
    app = create_app(db_path=db_file)
    return TestClient(app)


def test_health_endpoint(client: TestClient) -> None:
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "version" in data


def test_list_runs(client: TestClient, populated_db: tuple[Path, str, str]) -> None:
    _, run_1, run_2 = populated_db
    resp = client.get("/runs")
    assert resp.status_code == 200
    runs = resp.json()
    assert len(runs) == 2
    run_ids = [r["run_id"] for r in runs]
    assert run_1 in run_ids
    assert run_2 in run_ids


def test_list_runs_limit(client: TestClient) -> None:
    resp = client.get("/runs?limit=1")
    assert resp.status_code == 200
    runs = resp.json()
    assert len(runs) == 1


def test_get_run_detail(client: TestClient, populated_db: tuple[Path, str, str]) -> None:
    _, run_1, _ = populated_db
    resp = client.get(f"/runs/{run_1}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["run_id"] == run_1
    assert data["event_count"] == 3


def test_get_run_detail_not_found(client: TestClient) -> None:
    resp = client.get("/runs/nonexistent-run-id")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"]


def test_get_run_events(client: TestClient, populated_db: tuple[Path, str, str]) -> None:
    _, run_1, _ = populated_db
    resp = client.get(f"/runs/{run_1}/events")
    assert resp.status_code == 200
    events = resp.json()
    assert len(events) == 3
    types = [e["event_type"] for e in events]
    assert types == ["user_request", "tool_call", "final_response"]


def test_get_run_events_filtered(client: TestClient, populated_db: tuple[Path, str, str]) -> None:
    _, run_1, _ = populated_db
    resp = client.get(f"/runs/{run_1}/events?event_type={EventType.TOOL_CALL.value}")
    assert resp.status_code == 200
    events = resp.json()
    assert len(events) == 1
    assert events[0]["event_type"] == "tool_call"
    assert events[0]["tool_name"] == "read_sales_data"


def test_get_run_events_not_found(client: TestClient) -> None:
    resp = client.get("/runs/nonexistent-run-id/events")
    assert resp.status_code == 404


def test_verify_intact_chain(client: TestClient) -> None:
    resp = client.get("/verify")
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["events_checked"] == 5
    assert data["problem"] is None
    assert len(data["head_hash"]) == 64


def test_verify_tampered_chain(client: TestClient, populated_db: tuple[Path, str, str]) -> None:
    db_file, _, _ = populated_db
    import sqlite3

    conn = sqlite3.connect(db_file)
    conn.execute("DROP TRIGGER audit_no_update")
    conn.execute("UPDATE audit_events SET payload = '{\"tampered\": true}' WHERE seq = 2")
    conn.commit()
    conn.close()

    resp = client.get("/verify")
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is False
    assert data["problem"] is not None
    assert data["problem"]["seq"] == 2


def test_no_write_endpoints_exist(client: TestClient) -> None:
    """Verify that only read endpoints exist; any write attempts return 405 Method Not Allowed."""
    # POST to /runs
    post_resp = client.post("/runs", json={"test": "data"})
    assert post_resp.status_code == 405

    # DELETE to /runs/xyz
    del_resp = client.delete("/runs/some-id")
    assert del_resp.status_code == 405

    # PUT to /runs/xyz/events
    put_resp = client.put("/runs/some-id/events", json=[])
    assert put_resp.status_code == 405

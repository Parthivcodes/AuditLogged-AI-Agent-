"""Tests for the CLI commands."""

import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

from audit_agent.agent.loop import AgentRunResult
from audit_agent.audit.logger import AuditLogger
from audit_agent.cli import main
from audit_agent.storage.sqlite_store import SQLiteAuditStore


@pytest.fixture
def cli_db(tmp_path: Path):
    db_file = tmp_path / "cli_test.db"
    with SQLiteAuditStore(db_file) as store:
        logger = AuditLogger(store)
        run_id = logger.new_run_id()
        logger.user_request(run_id, "Summarize Q1")
        logger.decision(run_id, "final_answer", rationale="Analysis complete")
        logger.final_response(run_id, "Q1 Revenue was $1,000.")
    return db_file, run_id


def test_cli_help(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "Audit-Logged AI Agent CLI" in captured.out


def test_cli_list(cli_db: tuple[Path, str], capsys: pytest.CaptureFixture[str]) -> None:
    db_file, run_id = cli_db
    code = main(["list", "--db", str(db_file)])
    assert code == 0
    captured = capsys.readouterr()
    assert run_id in captured.out
    assert "RUN ID" in captured.out


def test_cli_list_empty(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db_file = tmp_path / "nonexistent.db"
    code = main(["list", "--db", str(db_file)])
    assert code == 0
    captured = capsys.readouterr()
    assert "No audit database found" in captured.out


def test_cli_show(cli_db: tuple[Path, str], capsys: pytest.CaptureFixture[str]) -> None:
    db_file, run_id = cli_db
    code = main(["show", run_id, "--db", str(db_file)])
    assert code == 0
    captured = capsys.readouterr()
    assert f"Run {run_id}" in captured.out
    assert "user_request" in captured.out
    assert "final_response" in captured.out


def test_cli_show_not_found(cli_db: tuple[Path, str], capsys: pytest.CaptureFixture[str]) -> None:
    db_file, _ = cli_db
    fake_id = str(uuid.uuid4())
    code = main(["show", fake_id, "--db", str(db_file)])
    assert code == 1
    captured = capsys.readouterr()
    assert "No events found" in captured.err


def test_cli_verify_ok(cli_db: tuple[Path, str], capsys: pytest.CaptureFixture[str]) -> None:
    db_file, _ = cli_db
    code = main(["verify", "--db", str(db_file)])
    assert code == 0
    captured = capsys.readouterr()
    assert "Hash chain integrity verified" in captured.out


def test_cli_verify_tampered(cli_db: tuple[Path, str], capsys: pytest.CaptureFixture[str]) -> None:
    db_file, _ = cli_db
    # Tamper with the database
    import sqlite3

    conn = sqlite3.connect(db_file)
    conn.execute("DROP TRIGGER audit_no_update")
    conn.execute("UPDATE audit_events SET payload = '{\"tampered\": true}' WHERE seq = 1")
    conn.commit()
    conn.close()

    code = main(["verify", "--db", str(db_file)])
    assert code == 1
    captured = capsys.readouterr()
    assert "TAMPER DETECTED" in captured.err


def test_cli_run_missing_api_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    code = main(["run", "Analyze data", "--db", str(tmp_path / "test.db")])
    assert code == 1
    captured = capsys.readouterr()
    assert "ANTHROPIC_API_KEY is not set" in captured.err


def test_cli_run_mocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-mock")
    db_file = tmp_path / "run_test.db"

    mock_result = AgentRunResult(
        run_id="test-run-1234",
        success=True,
        final_response="Analysis completed successfully.",
        error=None,
        step_count=3,
    )

    with patch("audit_agent.cli.AgentRunner.run", return_value=mock_result):
        code = main(["run", "Summarize Q1", "--db", str(db_file)])
        assert code == 0
        captured = capsys.readouterr()
        assert "=== Agent Result ===" in captured.out
        assert "Analysis completed successfully." in captured.out
        assert "test-run-1234" in captured.out

"""Command-line interface for the audit agent."""

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from audit_agent.agent.loop import AgentRunner
from audit_agent.agent.model_client import AnthropicModelClient
from audit_agent.audit.logger import AuditLogger
from audit_agent.audit.redaction import Redactor
from audit_agent.audit.timeline import render_timeline
from audit_agent.config import Settings
from audit_agent.storage.sqlite_store import SQLiteAuditStore
from audit_agent.tools.permissions import PermissionGuard
from audit_agent.tools.registry import create_default_registry


def _get_store(db_path: Path) -> SQLiteAuditStore:
    return SQLiteAuditStore(db_path)


def cmd_run(args: argparse.Namespace, settings: Settings) -> int:
    """Execute an agent run with complete audit logging."""
    api_key = settings.anthropic_api_key
    if not api_key:
        sys.stderr.write(
            "Error: ANTHROPIC_API_KEY is not set.\n"
            "Please configure ANTHROPIC_API_KEY in your .env file or environment.\n"
        )
        return 1

    db_path = Path(args.db) if args.db else settings.db_path
    model = args.model or settings.model
    max_steps = args.max_steps or settings.max_steps

    with _get_store(db_path) as store:
        redactor = Redactor(literal_secrets=[api_key])
        logger = AuditLogger(store, redactor=redactor)
        guard = PermissionGuard(data_dir=settings.data_dir, output_dir=settings.output_dir)
        registry = create_default_registry()
        client = AnthropicModelClient(api_key=api_key, default_model=model)

        runner = AgentRunner(
            model_client=client,
            logger=logger,
            registry=registry,
            guard=guard,
            model=model,
            max_steps=max_steps,
        )

        print(f"Starting audit run for prompt: {args.prompt!r}")
        print(f"Database: {db_path} | Model: {model} | Max steps: {max_steps}\n")

        result = runner.run(args.prompt)

        if result.success:
            print("\n=== Agent Result ===")
            print(result.final_response)
            print(f"\nCompleted in {result.step_count} step(s). Run ID: {result.run_id}")
            print(f"To view the tamper-evident audit timeline, run:\n  audit show {result.run_id}")
            return 0

        sys.stderr.write(f"\nRun failed: {result.error}\nRun ID: {result.run_id}\n")
        return 1


def cmd_show(args: argparse.Namespace, settings: Settings) -> int:
    """Show the full audit timeline for a specific run."""
    db_path = Path(args.db) if args.db else settings.db_path
    if not db_path.is_file():
        sys.stderr.write(f"Database file not found: {db_path}\n")
        return 1

    with _get_store(db_path) as store:
        events = store.get_run_events(args.run_id)
        if not events:
            sys.stderr.write(f"No events found for run ID: {args.run_id}\n")
            return 1

        timeline_text = render_timeline(events)
        print(timeline_text)
        return 0


def cmd_list(args: argparse.Namespace, settings: Settings) -> int:
    """List recent audit runs."""
    db_path = Path(args.db) if args.db else settings.db_path
    if not db_path.is_file():
        print(f"No audit database found at: {db_path}")
        return 0

    with _get_store(db_path) as store:
        runs = store.list_runs(limit=args.limit)
        if not runs:
            print(f"No audit runs found in {db_path}.")
            return 0

        header = f"{'RUN ID':<38} {'STARTED AT':<25} {'EVENTS':<8} {'NON-OK':<8} {'SEQ RANGE'}"
        print(header)
        print("-" * len(header))
        for r in runs:
            seq_range = f"{r.first_seq}..{r.last_seq}"
            print(
                f"{r.run_id:<38} {r.started_at:<25} {r.event_count:<8} "
                f"{r.non_ok_events:<8} {seq_range}"
            )
        return 0


def cmd_verify(args: argparse.Namespace, settings: Settings) -> int:
    """Verify hash chain integrity across all runs."""
    db_path = Path(args.db) if args.db else settings.db_path
    if not db_path.is_file():
        sys.stderr.write(f"Database file not found: {db_path}\n")
        return 1

    with _get_store(db_path) as store:
        result = store.verify()
        if result.ok:
            print("OK: Hash chain integrity verified successfully.")
            print(f"Events checked: {result.events_checked}")
            print(f"Head hash:       {result.head_hash}")
            return 0

        problem = result.problem
        seq = problem.seq if problem else "unknown"
        reason = problem.reason if problem else "unknown"
        sys.stderr.write("TAMPER DETECTED: Hash chain verification failed!\n")
        sys.stderr.write(f"Events checked before failure: {result.events_checked}\n")
        sys.stderr.write(f"Failed at seq:                 {seq}\n")
        sys.stderr.write(f"Reason:                        {reason}\n")
        return 1


def cmd_serve(args: argparse.Namespace, settings: Settings) -> int:
    """Run read-only API server (M7)."""
    import os

    import uvicorn

    host = args.host or settings.api_host
    port = args.port or settings.api_port
    db_path = Path(args.db) if args.db else settings.db_path
    os.environ["AUDIT_DB_PATH"] = str(db_path)
    print(f"Starting read-only audit API on http://{host}:{port}/docs (db: {db_path})")
    uvicorn.run("audit_agent.api.app:app", host=host, port=port)
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Construct argument parser with subcommands."""
    parser = argparse.ArgumentParser(
        prog="audit",
        description="Audit-Logged AI Agent CLI: Run agents with cryptographic audit trails.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # run
    p_run = subparsers.add_parser("run", help="Execute an agent task")
    p_run.add_argument("prompt", help="Prompt or task for the agent")
    p_run.add_argument("--model", help="Anthropic model name")
    p_run.add_argument("--max-steps", type=int, help="Maximum agent steps")
    p_run.add_argument("--db", help="Path to SQLite audit database")

    # show
    p_show = subparsers.add_parser("show", help="Display audit timeline for a run")
    p_show.add_argument("run_id", help="UUID of the run to display")
    p_show.add_argument("--db", help="Path to SQLite audit database")

    # list
    p_list = subparsers.add_parser("list", help="List recent audit runs")
    p_list.add_argument("--limit", type=int, default=20, help="Maximum runs to display")
    p_list.add_argument("--db", help="Path to SQLite audit database")

    # verify
    p_verify = subparsers.add_parser("verify", help="Verify cryptographic hash chain integrity")
    p_verify.add_argument("--db", help="Path to SQLite audit database")

    # serve
    p_serve = subparsers.add_parser("serve", help="Run read-only API server")
    p_serve.add_argument("--host", help="Server host")
    p_serve.add_argument("--port", type=int, help="Server port")
    p_serve.add_argument("--db", help="Path to SQLite audit database")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)
    settings = Settings.from_env()

    commands = {
        "run": cmd_run,
        "show": cmd_show,
        "list": cmd_list,
        "verify": cmd_verify,
        "serve": cmd_serve,
    }

    handler = commands.get(args.command)
    if handler:
        return handler(args, settings)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())

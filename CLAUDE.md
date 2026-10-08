# CLAUDE.md — Audit-Logged AI Agent

## Overview
A Python AI agent where every run is fully auditable. Each step emits a structured,
redacted, hash-chained event recording TOOLS used, DATA accessed, DECISIONS made, and
the model's stated RATIONALE. Core principle: if you can't trace it, you can't trust it.
Read `docs/PROJECT_BRIEF.md`, `docs/ARCHITECTURE.md`, `docs/AUDIT_SCHEMA.md` before changes.
Work milestone-by-milestone from `docs/TASKS.md`; stop after each milestone for review.

## Stack
- Python 3.12, `anthropic` SDK (model from `AUDIT_AGENT_MODEL`)
- pydantic v2 (event models), SQLite via stdlib `sqlite3`, `hashlib` SHA-256
- argparse CLI (`audit` console script), FastAPI + uvicorn (read-only API)
- pytest (+ httpx for API tests), ruff for lint/format
- `.env` loaded by a small stdlib loader in `config.py` (no python-dotenv)

## Structure
- `src/audit_agent/agent/`   agent loop, prompts, ModelClient (Anthropic + protocol)
- `src/audit_agent/tools/`   tool specs, registry, allowlist/PermissionGuard
- `src/audit_agent/audit/`   event models, redaction, hash chain, logger, timeline
- `src/audit_agent/storage/` SQLite append-only store
- `src/audit_agent/api/`     FastAPI read-only routes
- `src/audit_agent/cli.py`   `audit run|show|list|verify|serve`
- `data/sample/`             demo CSV;  `output/` tool-written summaries (gitignored)
- `tests/`                   offline pytest suite (FakeModelClient in conftest)

## Commands
```bash
python -m venv .venv
.venv\Scripts\activate            # Windows  (source .venv/bin/activate on Unix)
pip install -e ".[dev]"
copy .env.example .env            # then set ANTHROPIC_API_KEY
pytest -q                         # full offline suite
ruff check . && ruff format --check .
audit run "Summarize Q1 sales data"
audit list
audit show <run_id>
audit verify                      # recompute hash chain
audit serve                       # FastAPI on http://127.0.0.1:8000/docs
```

## Conventions
- Type hints everywhere; pydantic models for anything crossing a boundary.
- All audit writes go through `AuditLogger` (redact → chain → store). One choke point.
- Every tool: declared in `tools/`, registered in `registry.py`, gated by `permissions.py`,
  receives a `ToolContext`, and emits `data_access` events for each read/write.
- Every tool schema includes a required `rationale` string (auto-injected by `base.py`).
- Timestamps: UTC ISO-8601 with ms and `Z`. IDs: UUID4 strings.
- Canonical JSON for hashing: `sort_keys=True, separators=(",", ":")`, UTF-8.
- One global hash chain across all runs; genesis `prev_hash` is 64 zeros.
- Redaction uses irreversible masks: `[REDACTED:<type>]`. All redaction logic lives in
  `audit/redaction.py` only, so a hashed-token strategy can be added later.
- Tool results are logged only as redacted previews (≤ 500 chars).
- Agent tests use `FakeModelClient` with scripted responses; assert the exact event sequence.
- Add a test for every new event field, tool, or redaction pattern.
- Small, focused modules; no module over ~300 lines.
- Config only via `config.Settings` (env vars); no hardcoded paths, models, or keys.

## Never Do
- NEVER write audit data without passing through redaction first.
- NEVER add UPDATE/DELETE paths for `audit_events`, or drop/alter its triggers.
- NEVER request, enable, or log hidden/extended thinking; log only stated rationale + visible text.
- NEVER call the real Anthropic API in tests.
- NEVER commit `.env`, API keys, `*.db`, or `output/`.
- NEVER let tools touch paths outside `data/` (read) and `output/` (write).
- NEVER execute a tool without `PermissionGuard` approval; never skip logging a denial.
- NEVER change the event schema or canonical JSON without bumping `schema_version`
  and updating `docs/AUDIT_SCHEMA.md`.
- NEVER add a dependency without explicit approval from the user.
- NEVER start the next milestone without the user's go-ahead.

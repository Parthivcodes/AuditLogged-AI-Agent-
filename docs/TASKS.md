# Tasks & Milestones

Each milestone = one session. Finish with green tests, then stop for review.

## M0 — Scaffolding ✅
- [x] Folder tree, empty packages with `__init__.py`
- [x] pyproject.toml (deps, `audit` script, pytest + ruff config), .env.example, .gitignore
- [x] CLAUDE.md, README stub, docs/*
- DoD: `pip install -e ".[dev]"` succeeds; `pytest` runs (0 tests).

## M1 — Event Model & Redaction ✅
- [x] `audit/events.py`: AuditEvent + enums (EventType, Actor, Status, DataOperation)
- [x] `audit/redaction.py`: patterns (Anthropic/OpenAI keys, bearer tokens, AWS keys,
      emails, phones, credit cards) + sensitive key names (password, token, api_key, secret…)
- [x] Recursive redaction over dicts/lists/strings; returns redaction tags
- [x] `tests/test_redaction.py` (+ `tests/test_events.py`)
- DoD: seeded secrets/PII never survive redaction; tags correct.

## M2 — Hash Chain & Append-Only Store ✅
- [x] `audit/hashchain.py`: canonical_json, compute_hash, verify_chain
- [x] `storage/sqlite_store.py`: schema, triggers, transactional append (BEGIN IMMEDIATE),
      reads: list_runs, get_run_events, iter_all
- [x] `tests/test_hash_chain.py`: valid chain; detects edit, delete, reorder, insert;
      UPDATE/DELETE blocked by triggers
- DoD: tamper tests all fail verification as expected.

## M3 — AuditLogger & Timeline ✅
- [x] `audit/logger.py`: build → redact → chain → store; per-run step counter
- [x] `audit/timeline.py`: readable plain-text per-run timeline
- [x] `tests/test_audit_logger.py`
- DoD: logged events round-trip from DB with correct fields and hashes.

## M4 — Tools, Permissions & Sample Data ✅
- [x] `data/sample/sales_q1.csv` (~60 rows, includes customer name/email)
- [x] `tools/base.py` (Tool spec, ToolContext, rationale injection), `registry.py`
- [x] `tools/sales.py`, `tools/summary.py`, `tools/restricted.py`
- [x] `tools/permissions.py`: allowlist + path sandbox
- [x] `tests/test_tools.py`: outputs, data_access events, sandbox + denial
- DoD: tools work standalone; denied/out-of-sandbox calls never execute.

## M5 — Model Client & Agent Loop ✅
- [x] `config.py`: Settings from env + stdlib `.env` loader
- [x] `agent/model_client.py`: ModelClient protocol, AnthropicModelClient
- [x] `agent/prompts.py`: system prompt (rationale requirement, tool usage guidance)
- [x] `agent/loop.py`: AgentRunner with max steps, token/latency capture, error handling
- [x] `tests/conftest.py` FakeModelClient; `tests/test_agent_run.py`
      (happy path, denied tool, missing rationale, tool exception, max-steps exceeded)
- DoD: scripted runs produce the exact expected event sequence; chain verifies.

## M6 — CLI ✅
- [x] `cli.py`: `audit run`, `show`, `list`, `verify`, `serve`
- [x] Unit test suite covering all CLI subcommands (`tests/test_cli.py`)
- [ ] Manual smoke test against real API with demo prompt (ready once user sets `ANTHROPIC_API_KEY` in `.env`)
- DoD: end-to-end demo works; `audit show` output reviewed and approved.

## M7 — Read-Only API ✅
- [x] `api/app.py`, `api/routes.py`: GET /health, /runs, /runs/{id},
      /runs/{id}/events?event_type=, /verify
- [x] `audit serve` command
- [x] `tests/test_api.py`
- DoD: endpoints return schema-valid data; no write endpoints exist.

## M8 — Hardening & Docs ✅
- [x] Tamper demo section in README (edit DB → verify fails)
- [x] Edge cases: empty CSV, huge args truncation, unicode, concurrent append test
- [x] README walkthrough with sample timeline output
- DoD: all success criteria in PROJECT_BRIEF met.

## Backlog (post-v1)
- Salted-hash redaction tokens; chain-head export/signing; JSONL export; OpenTelemetry bridge
- Optional `rich` timeline rendering (requires dependency approval)

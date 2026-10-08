# Project Brief — Audit-Logged AI Agent

## Problem
AI agents call tools, read data, and make decisions that are usually invisible after the fact.
If you can't trace what an agent did, you can't debug it, secure it, or trust it.

## Goal
An AI agent where every run produces a complete, tamper-evident audit trail answering:
- **Tools** — what did it use?
- **Data** — what did it access?
- **Decisions** — what did it decide?
- **Reasoning** — why? (the model's *stated* rationale, never hidden chain-of-thought)

## Demo Scenario
User: "Summarize Q1 sales data" → agent calls `read_sales_data` → `calculate_stats` →
`write_summary`. A forbidden `export_customer_list` attempt is denied and logged.
`audit show <run_id>` replays the full timeline; `audit verify` proves integrity.

## In Scope (v1)
- Agent loop on the Anthropic SDK, model set via env var
- Structured audit events: user_request, tool_call, data_access, decision, final_response, error
- Required `rationale` on every tool call; visible model explanation captured
- Redaction of secrets and PII before anything is persisted
- Append-only SQLite store (DB triggers) + SHA-256 hash chain + verify command
- Tool allowlist with sandboxed file paths; denials logged
- CLI: run, show, list, verify, serve
- Read-only FastAPI endpoints for querying runs/events
- Offline pytest suite using a scripted fake model client

## Non-Goals (v1)
- Logging hidden/extended thinking
- Multi-user auth, RBAC, or multi-tenant storage
- Distributed / concurrent writers, external log shipping, WORM storage
- Web UI dashboard
- Cryptographic signing / external anchoring of the chain head (future)

## Users
- Developers debugging agent behavior
- Security/compliance reviewers auditing what data an agent touched

## Success Criteria
1. 100% of agent steps in a run produce an audit event; each run ends in final_response or error.
2. `audit verify` passes on an untouched DB and fails on any edited, deleted, or reordered row.
3. No raw secret or PII value from the sample data appears anywhere in the DB.
4. Every tool_call event has a non-empty rationale.
5. Denied tool attempts are logged with status=denied and never executed.
6. `audit show <run_id>` lets a reviewer understand a run in under a minute.
7. Test suite runs offline and green.

## Risks & Mitigations
| Risk | Mitigation |
|---|---|
| Model omits rationale | Schema marks it required; missing → logged as error, tool not run |
| Redaction misses a pattern | Redact at a single choke point (AuditLogger); tests with seeded PII |
| Whole-DB replacement defeats chain | Documented limitation; future: export/anchor chain head |
| Log bloat from tool output | Truncated, redacted result previews only |

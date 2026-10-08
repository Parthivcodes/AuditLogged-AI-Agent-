# Audit-Logged AI Agent

An AI agent where every single step is fully auditable. Each run emits a structured, redacted, cryptographically hash-chained event recording **TOOLS** used, **DATA** accessed, **DECISIONS** made, and the model's stated **RATIONALE**.

> **Core Principle**: If you can't trace it, you can't debug it, secure it, or trust it.

---

## Key Features

- **Tamper-Evident Hash Chain**: Every event is cryptographically linked to the previous event using SHA-256 (`canonical_json`). Any modification, deletion, reordering, or row insertion breaks the chain and is detected by `audit verify`.
- **Append-Only Database**: SQLite storage guarded by database triggers preventing `UPDATE` and `DELETE`. All writes run inside `BEGIN IMMEDIATE` transactions.
- **Strict Redaction Choke Point**: All data flows through `AuditLogger` before being hashed or persisted. Automatically detects and irreversibly masks API keys (Anthropic, OpenAI, AWS), bearer tokens, credit cards (Luhn-checked), email addresses, phone numbers, and sensitive dictionary keys (`password`, `api_key`, `secret`).
- **Required Model Rationale**: Every tool definition auto-injects a mandatory `rationale` requirement. Tool invocations without explicit rationale are rejected and logged as errors.
- **Sandboxed Tool Permissions**: `PermissionGuard` enforces tool allowlists and restricts file reads to `data/` and writes to `output/`. Path traversal attempts (`../`) are strictly blocked.
- **Human-Readable Timeline**: Review runs in under a minute with `audit show <run_id>`.
- **Read-Only API**: FastAPI query endpoints for auditing without any risk of database tampering.
- **100% Offline Test Suite**: Complete unit and integration test suite with `FakeModelClient` test doubles.

---

## Installation & Setup

```bash
# 1. Create and activate virtual environment (Python 3.12+)
python -m venv .venv
.venv\Scripts\activate            # Windows (source .venv/bin/activate on Linux/macOS)

# 2. Install dependencies in editable mode
pip install -e ".[dev]"

# 3. Configure environment
copy .env.example .env            # cp .env.example .env on Linux/macOS
# Edit .env and set ANTHROPIC_API_KEY
```

---

## CLI Usage & Walkthrough

### 1. Run the Agent
```bash
audit run "Summarize Q1 sales data"
```
```text
Starting audit run for prompt: 'Summarize Q1 sales data'
Database: audit.db | Model: claude-sonnet-4-5 | Max steps: 10

=== Agent Result ===
Q1 Total Revenue was $116,420 across North, South, East, and West regions.
Top performing product was Widget Pro.

Completed in 4 step(s). Run ID: 7f3a1290-b384-48f1-a1e9-4411d9f82873
To view the tamper-evident audit timeline, run:
  audit show 7f3a1290-b384-48f1-a1e9-4411d9f82873
```

### 2. View Recent Runs
```bash
audit list
```
```text
RUN ID                                 STARTED AT                EVENTS   NON-OK   SEQ RANGE
--------------------------------------------------------------------------------------------
7f3a1290-b384-48f1-a1e9-4411d9f82873   2026-10-07T14:32:01.102Z  8        0        1..8
```

### 3. Inspect the Audit Timeline
```bash
audit show 7f3a1290-b384-48f1-a1e9-4411d9f82873
```
```text
====================================================================================================
Run 7f3a1290-b384-48f1-a1e9-4411d9f82873
8 events  |  2026-10-07T14:32:01.102Z -> 2026-10-07T14:32:06.450Z
====================================================================================================
[00] 14:32:01.102  user_request    user
       request:   Summarize Q1 sales data
[01] 14:32:02.310  decision        agent  call_tool:read_sales_data
       why:       Need raw Q1 transactions to calculate sales statistics.
       said:      I will load the Q1 sales dataset.
       meta:      model claude-sonnet-4-5 | tokens 420 in / 65 out | 1208 ms
[02] 14:32:02.314  data_access     tool   READ data/sample/sales_q1.csv
       touched:   60 records; fields: order_id, date, region, product, units, unit_price, revenue, customer_name, customer_email
[03] 14:32:02.315  tool_call       tool   read_sales_data
       why:       Need raw Q1 transactions to calculate sales statistics.
       args:      {"dataset": "sample/sales_q1.csv"}
       result:    {"dataset": "data/sample/sales_q1.csv", "total_records": 60, "returned_records": 60...}
       meta:      4 ms
[04] 14:32:04.102  decision        agent  call_tool:calculate_stats
       why:       Calculate total revenue and breakdowns by region and product.
       said:      Now calculating summary aggregations.
       meta:      model claude-sonnet-4-5 | tokens 1250 in / 80 out | 1780 ms
[05] 14:32:04.105  data_access     tool   READ data/sample/sales_q1.csv
       touched:   60 records; fields: revenue, units, product, region
[06] 14:32:04.106  tool_call       tool   calculate_stats
       why:       Calculate total revenue and breakdowns by region and product.
       args:      {"dataset": "sample/sales_q1.csv"}
       result:    {"total_orders": 60, "total_revenue": 116420.0, "total_units_sold": 1280...}
       meta:      2 ms
[07] 14:32:06.450  final_response  agent  final_answer
       answer:    Q1 Total Revenue was $116,420 across North, South, East, and West regions...
       meta:      model claude-sonnet-4-5 | tokens 1890 in / 110 out
----------------------------------------------------------------------------------------------------
Outcome:   completed  (0 denied, 0 errors)
Events:    data_access=2, decision=2, final_response=1, tool_call=2, user_request=1
Tools:     calculate_stats x1, read_sales_data x1
Data:      data/sample/sales_q1.csv
Tokens:    3560 in / 255 out
Redacted:  nothing
Chain:     seq 1-8, head e3b0c44298fc1c14...
```

---

## Tamper-Evident Verification & Tamper Demo

The audit log is secured by a continuous SHA-256 hash chain where each event includes the cryptographic hash of the preceding event (`prev_hash`).

### Normal Verification
```bash
audit verify
```
```text
OK: Hash chain integrity verified successfully.
Events checked: 8
Head hash:       e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

### Tamper Demonstration

Even if an attacker bypasses application-level security and directly manipulates the SQLite database file:

```bash
# 1. Attempting an UPDATE or DELETE inside SQLite is blocked by triggers:
sqlite3 audit.db "UPDATE audit_events SET status = 'denied' WHERE seq = 2;"
# Error: stepping, append-only (19)

# 2. If an attacker disables triggers and alters a row:
sqlite3 audit.db "DROP TRIGGER audit_no_update; UPDATE audit_events SET payload = '{\"tampered\": true}' WHERE seq = 2;"

# 3. Running 'audit verify' immediately flags the tampering:
audit verify
```
```text
TAMPER DETECTED: Hash chain verification failed!
Events checked before failure: 1
Failed at seq:                 2
Reason:                        hash mismatch: event content was modified
```

---

## Read-Only API Server

Launch the read-only FastAPI query service:

```bash
audit serve --port 8000
```

Interactive documentation is available at [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs).

### Endpoints
- `GET /health` — Service health status
- `GET /runs` — List recent runs (`?limit=50`)
- `GET /runs/{run_id}` — Summary of a single run
- `GET /runs/{run_id}/events` — All audit events for a run (`?event_type=tool_call`)
- `GET /verify` — Recompute and verify the global hash chain

*Note: All mutating HTTP methods (`POST`, `PUT`, `DELETE`, `PATCH`) return `405 Method Not Allowed`.*

---

## Running Tests

Run the full offline test suite:

```bash
pytest -q
ruff check . && ruff format --check .
```

---

## Documentation

- [Project Brief](docs/PROJECT_BRIEF.md): Mission, scope, and success criteria
- [Architecture](docs/ARCHITECTURE.md): Component interactions, lifecycle, and design decisions
- [Audit Schema](docs/AUDIT_SCHEMA.md): Formal JSON schema for audit events v1.0
- [Tasks & Milestones](docs/TASKS.md): Implementation milestone breakdown

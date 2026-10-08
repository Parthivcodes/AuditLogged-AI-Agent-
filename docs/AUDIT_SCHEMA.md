# Audit Event Schema — v1.0

Every agent step emits one `AuditEvent`. Events are redacted, hash-chained, and appended
to the `audit_events` SQLite table. Rows can never be updated or deleted.

## Event Types
| `event_type` | Emitted when |
|---|---|
| `user_request` | A run starts with the user's prompt |
| `decision` | The model chooses an action (`call_tool:<name>`, `final_answer`, `deny:<name>`) |
| `tool_call` | A tool was executed (`ok`/`error`) or blocked (`denied`) |
| `data_access` | A tool read or wrote a data source |
| `final_response` | The model ends the run with an answer |
| `error` | Any failure (model error, missing rationale, tool exception, max steps) |

## Fields
| Field | Type | Req | Notes |
|---|---|---|---|
| `schema_version` | `str` | ✔ | `"1.0"` |
| `seq` | `int` | ✔ | Global sequence; SQLite PK; assigned inside append transaction |
| `event_id` | `str` (UUID4) | ✔ | |
| `run_id` | `str` (UUID4) | ✔ | |
| `step_id` | `int` | ✔ | Monotonic within a run, starting at 0 |
| `timestamp` | `str` | ✔ | ISO-8601 UTC with ms, e.g. `2026-10-06T10:33:12.481Z` |
| `event_type` | enum | ✔ | See above |
| `actor` | enum | ✔ | `user \| agent \| tool \| system` |
| `status` | enum | ✔ | `ok \| error \| denied` |
| `model` | `str \| null` | | Model ID for model-driven events |
| `tool_name` | `str \| null` | | |
| `tool_args` | `object \| null` | | **Redacted**; `rationale` extracted to its own field |
| `result_preview` | `str \| null` | | Redacted, ≤ 500 chars |
| `data_source` | `str \| null` | | e.g. `data/sample/sales_q1.csv` |
| `data_operation` | enum \| null | | `read \| write` |
| `records_touched` | `int \| null` | | Rows read/written |
| `fields_accessed` | `list[str] \| null` | | Column names (values never stored) |
| `decision` | `str \| null` | | |
| `rationale` | `str \| null` | | Model's short rationale (required tool input) |
| `model_explanation` | `str \| null` | | Visible assistant text (redacted); never hidden reasoning |
| `content` | `str \| null` | | User request or final response text (redacted) |
| `error` | `object \| null` | | `{ "type": str, "message": str }` (redacted) |
| `latency_ms` | `float \| null` | | Model call or tool execution duration |
| `tokens` | `object \| null` | | `{ "input": int, "output": int }` |
| `redactions` | `list[str]` | ✔ | Types redacted in this event, e.g. `["email"]` |
| `prev_hash` | `str` (64 hex) | ✔ | Hash of event `seq - 1`; genesis = `"0" * 64` |
| `hash` | `str` (64 hex) | ✔ | `sha256(canonical_json(event_without_hash))` |

## Hashing Rules
- Canonical JSON: `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`,
  encoded UTF-8.
- The hashed object is the full event **minus** the `hash` field (includes `seq` and `prev_hash`).
- One **global** chain across all runs.
- `audit verify` recomputes every hash in `seq` order and checks `prev_hash` linkage and
  `seq` continuity; any edit, deletion, insertion, or reordering fails verification.
- Any change to fields or canonicalization requires bumping `schema_version`.

## Redaction Rules
- Applied by `AuditLogger` before hashing/storage, to: `tool_args`, `result_preview`,
  `content`, `model_explanation`, `rationale`, `decision`, `error.message`.
- `result_preview` is truncated to 500 chars **after** redaction, so truncation can never
  split a secret into a fragment the patterns no longer recognize.
- Value patterns: Anthropic/OpenAI-style keys, bearer tokens, AWS access keys, emails,
  phone numbers, credit card numbers.
- Key-name denylist (case-insensitive): `password`, `secret`, `token`, `api_key`,
  `apikey`, `authorization`, `credential`.
- Replacement: `[REDACTED:<type>]`; the type is appended to `redactions`.

## SQLite Table
```sql
CREATE TABLE audit_events (
  seq INTEGER PRIMARY KEY, event_id TEXT UNIQUE NOT NULL, run_id TEXT NOT NULL,
  step_id INTEGER NOT NULL, timestamp TEXT NOT NULL, event_type TEXT NOT NULL,
  status TEXT NOT NULL, tool_name TEXT, payload TEXT NOT NULL,   -- full canonical JSON
  prev_hash TEXT NOT NULL, hash TEXT UNIQUE NOT NULL
);
CREATE INDEX ix_audit_run ON audit_events(run_id, step_id);
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_events
  BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_events
  BEGIN SELECT RAISE(ABORT, 'append-only'); END;
```

## Examples

### user_request
```json
{
  "schema_version": "1.0", "seq": 41,
  "event_id": "9b1c...e2", "run_id": "r-7f3a...", "step_id": 0,
  "timestamp": "2026-10-06T10:33:12.481Z",
  "event_type": "user_request", "actor": "user", "status": "ok",
  "content": "Summarize Q1 sales data",
  "redactions": [],
  "prev_hash": "a41f...c0", "hash": "5d22...9e"
}
```

### decision
```json
{
  "schema_version": "1.0", "seq": 42, "run_id": "r-7f3a...", "step_id": 1,
  "timestamp": "2026-10-06T10:33:13.902Z",
  "event_type": "decision", "actor": "agent", "status": "ok",
  "model": "claude-sonnet-4-5",
  "decision": "call_tool:read_sales_data",
  "rationale": "Need the raw Q1 rows before computing any statistics.",
  "model_explanation": "I'll start by loading the Q1 sales dataset.",
  "latency_ms": 1380.4, "tokens": {"input": 812, "output": 96},
  "redactions": [], "prev_hash": "5d22...9e", "hash": "c7e0...14"
}
```

### data_access
```json
{
  "schema_version": "1.0", "seq": 43, "run_id": "r-7f3a...", "step_id": 2,
  "event_type": "data_access", "actor": "tool", "status": "ok",
  "tool_name": "read_sales_data",
  "data_source": "data/sample/sales_q1.csv", "data_operation": "read",
  "records_touched": 60,
  "fields_accessed": ["order_id","date","region","product","units","revenue","customer_email"],
  "redactions": [], "prev_hash": "c7e0...14", "hash": "19ab...77"
}
```

### tool_call (ok)
```json
{
  "schema_version": "1.0", "seq": 44, "run_id": "r-7f3a...", "step_id": 3,
  "event_type": "tool_call", "actor": "tool", "status": "ok",
  "tool_name": "read_sales_data",
  "tool_args": {"dataset": "sales_q1"},
  "rationale": "Need the raw Q1 rows before computing any statistics.",
  "result_preview": "60 rows; sample: {order_id: 1001, region: 'North', customer_email: '[REDACTED:email]'}",
  "latency_ms": 4.2, "redactions": ["email"],
  "prev_hash": "19ab...77", "hash": "e803...2d"
}
```

### tool_call (denied)
```json
{
  "schema_version": "1.0", "seq": 49, "run_id": "r-7f3a...", "step_id": 8,
  "event_type": "tool_call", "actor": "agent", "status": "denied",
  "tool_name": "export_customer_list",
  "tool_args": {"format": "csv"},
  "decision": "deny:export_customer_list",
  "rationale": "User may want a list of top customers.",
  "error": {"type": "PermissionDenied", "message": "Tool 'export_customer_list' is not in the allowlist"},
  "redactions": [], "prev_hash": "77c1...0a", "hash": "b2f4...e1"
}
```

### final_response
```json
{
  "schema_version": "1.0", "seq": 52, "run_id": "r-7f3a...", "step_id": 11,
  "event_type": "final_response", "actor": "agent", "status": "ok",
  "model": "claude-sonnet-4-5", "decision": "final_answer",
  "content": "Q1 revenue was $482,310 (+12% vs plan). North led with 38%...",
  "latency_ms": 2210.7, "tokens": {"input": 3420, "output": 388},
  "redactions": [], "prev_hash": "0d9e...55", "hash": "f1aa...c3"
}
```

"""Plain-text, per-run timeline for reviewers (``audit show``).

The goal is a run you can understand in under a minute: one header line per step,
indented detail lines for what matters (rationale, data touched, errors), and a
summary footer. Output is ASCII-only apart from logged content, so it renders on any
console. All text shown is already redacted at write time.
"""

import json
import textwrap
from collections import Counter
from collections.abc import Sequence

from audit_agent.audit.events import AuditEvent, EventType, Status

WIDTH = 100
_DETAIL_INDENT = " " * 7
_MAX_DETAIL_CHARS = 600


def _clip(text: str, limit: int = _MAX_DETAIL_CHARS) -> str:
    text = " ".join(text.split())  # collapse newlines/whitespace onto one logical line
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _detail(label: str, text: str) -> list[str]:
    first = f"{_DETAIL_INDENT}{label + ':':<10} "
    return textwrap.wrap(
        _clip(text),
        width=WIDTH,
        initial_indent=first,
        subsequent_indent=" " * len(first),
        break_long_words=True,
    )


def _time(ts: str) -> str:
    return ts[11:23]  # HH:MM:SS.mmm


def _headline(event: AuditEvent) -> str:
    marker = {Status.OK: "", Status.ERROR: "!! ERROR", Status.DENIED: "XX DENIED"}[event.status]
    subject = ""
    match event.event_type:
        case EventType.DECISION | EventType.FINAL_RESPONSE:
            subject = event.decision or ""
        case EventType.TOOL_CALL:
            subject = event.tool_name or ""
        case EventType.DATA_ACCESS:
            op = event.data_operation.value.upper() if event.data_operation else "?"
            subject = f"{op} {event.data_source}"
        case EventType.ERROR:
            subject = event.error.type if event.error else ""
    head = (
        f"[{event.step_id:02d}] {_time(event.timestamp)}  "
        f"{event.event_type.value:<15} {event.actor.value:<6} {subject}"
    )
    return f"{head}  {marker}".rstrip()


def _details(event: AuditEvent) -> list[str]:
    lines: list[str] = []
    if event.content is not None:
        lines += _detail("request" if event.event_type is EventType.USER_REQUEST else "answer",
                         event.content)  # fmt: skip
    if event.rationale:
        lines += _detail("why", event.rationale)
    if event.model_explanation:
        lines += _detail("said", event.model_explanation)
    if event.tool_args:
        lines += _detail("args", json.dumps(event.tool_args, ensure_ascii=False, sort_keys=True))
    if event.event_type is EventType.DATA_ACCESS:
        parts = []
        if event.records_touched is not None:
            parts.append(f"{event.records_touched} records")
        if event.fields_accessed:
            parts.append("fields: " + ", ".join(event.fields_accessed))
        if parts:
            lines += _detail("touched", "; ".join(parts))
    if event.result_preview:
        lines += _detail("result", event.result_preview)
    if event.error is not None:
        lines += _detail("error", f"{event.error.type}: {event.error.message}")
    meta = []
    if event.model:
        meta.append(f"model {event.model}")
    if event.tokens:
        meta.append(f"tokens {event.tokens.input} in / {event.tokens.output} out")
    if event.latency_ms is not None:
        meta.append(f"{event.latency_ms:.0f} ms")
    if event.redactions:
        meta.append("redacted: " + ", ".join(event.redactions))
    if meta:
        lines += _detail("meta", " | ".join(meta))
    return lines


def _footer(events: Sequence[AuditEvent]) -> list[str]:
    by_type = Counter(e.event_type.value for e in events)
    tools = Counter(e.tool_name for e in events if e.event_type is EventType.TOOL_CALL)
    sources = sorted({e.data_source for e in events if e.data_source})
    denied = sum(e.status is Status.DENIED for e in events)
    errors = sum(e.status is Status.ERROR for e in events)
    tok_in = sum(e.tokens.input for e in events if e.tokens)
    tok_out = sum(e.tokens.output for e in events if e.tokens)
    redacted = sorted({tag for e in events for tag in e.redactions})
    last = events[-1]
    outcome = "completed" if last.event_type is EventType.FINAL_RESPONSE else (
        "failed" if last.event_type is EventType.ERROR else "incomplete"
    )  # fmt: skip
    rule = "-" * WIDTH
    return [
        rule,
        f"Outcome:   {outcome}  ({denied} denied, {errors} errors)",
        "Events:    " + ", ".join(f"{k}={v}" for k, v in sorted(by_type.items())),
        "Tools:     " + (", ".join(f"{k} x{v}" for k, v in sorted(tools.items())) or "none"),
        "Data:      " + (", ".join(sources) or "none"),
        f"Tokens:    {tok_in} in / {tok_out} out",
        "Redacted:  " + (", ".join(redacted) or "nothing"),
        f"Chain:     seq {events[0].seq}-{last.seq}, head {last.hash[:16]}...",
    ]


def render_timeline(events: Sequence[AuditEvent]) -> str:
    """Render one run's events (in step order) as a readable plain-text timeline."""
    if not events:
        return "No events for this run."
    ordered = sorted(events, key=lambda e: (e.step_id, e.seq))
    first, last = ordered[0], ordered[-1]
    rule = "=" * WIDTH
    lines = [
        rule,
        f"Run {first.run_id}",
        f"{len(ordered)} events  |  {first.timestamp} -> {last.timestamp}",
        rule,
    ]
    for event in ordered:
        lines.append(_headline(event))
        lines.extend(_details(event))
    lines.extend(_footer(ordered))
    return "\n".join(lines)

"""AuditLogger: the single choke point for writing audit events.

Every event goes through the same pipeline: **build → redact → chain → store**.

1. Build an ``AuditEventBody`` from the caller's fields, with the next per-run ``step_id``.
2. Redact every free-text and structured field that could carry secrets or PII
   (``tool_args``, ``result_preview``, ``content``, ``model_explanation``, ``rationale``,
   ``decision``, ``error.message``) and record the redaction kinds in ``redactions``.
3. Truncate ``result_preview`` to the limit *after* redaction, so a secret cut in half
   by truncation can never slip past the patterns.
4. Hand the redacted body to the store, which chains and appends it atomically.

Nothing else in the codebase should call ``SQLiteAuditStore.append`` directly.
"""

import threading
from collections.abc import Mapping
from typing import Any

from audit_agent.audit.events import (
    MAX_PREVIEW_CHARS,
    Actor,
    AuditEvent,
    AuditEventBody,
    DataOperation,
    ErrorInfo,
    EventType,
    Status,
    TokenUsage,
    new_id,
)
from audit_agent.audit.redaction import Redactor
from audit_agent.storage.sqlite_store import SQLiteAuditStore

RATIONALE_KEY = "rationale"
_ELLIPSIS = "…"

# String fields that are redacted as free text.
_TEXT_FIELDS = ("result_preview", "content", "model_explanation", "rationale", "decision")


def truncate(text: str, limit: int = MAX_PREVIEW_CHARS) -> str:
    """Cut ``text`` to at most ``limit`` characters, marking the cut with an ellipsis."""
    return text if len(text) <= limit else text[: limit - len(_ELLIPSIS)] + _ELLIPSIS


def error_info(exc: BaseException) -> ErrorInfo:
    """Unredacted ``ErrorInfo`` from an exception. The logger redacts the message."""
    return ErrorInfo(type=type(exc).__name__, message=str(exc))


class AuditLogger:
    """Builds, redacts, and persists audit events, numbering steps per run."""

    def __init__(self, store: SQLiteAuditStore, redactor: Redactor | None = None) -> None:
        self._store = store
        self._redactor = redactor or Redactor()
        self._next_step: dict[str, int] = {}
        self._lock = threading.Lock()

    @staticmethod
    def new_run_id() -> str:
        return new_id()

    # Core

    def log(
        self,
        run_id: str,
        event_type: EventType,
        actor: Actor,
        *,
        status: Status = Status.OK,
        **fields: Any,
    ) -> AuditEvent:
        """Redact and persist one event. Raises ``ValueError`` if the event is invalid.

        A rejected event consumes no step number and writes nothing.
        """
        redacted, tags = self._redact_fields(fields)
        with self._lock:
            step_id = self._peek_step(run_id)
            body = AuditEventBody(
                run_id=run_id,
                step_id=step_id,
                event_type=event_type,
                actor=actor,
                status=status,
                redactions=tags,
                **redacted,
            )
            event = self._store.append(body)
            self._next_step[run_id] = step_id + 1
        return event

    # Typed helpers, one per event type

    def user_request(self, run_id: str, content: str) -> AuditEvent:
        return self.log(run_id, EventType.USER_REQUEST, Actor.USER, content=content)

    def decision(
        self,
        run_id: str,
        decision: str,
        *,
        rationale: str | None = None,
        model_explanation: str | None = None,
        model: str | None = None,
        tool_name: str | None = None,
        latency_ms: float | None = None,
        tokens: TokenUsage | None = None,
    ) -> AuditEvent:
        return self.log(
            run_id,
            EventType.DECISION,
            Actor.AGENT,
            decision=decision,
            rationale=rationale,
            model_explanation=model_explanation,
            model=model,
            tool_name=tool_name,
            latency_ms=latency_ms,
            tokens=tokens,
        )

    def tool_call(
        self,
        run_id: str,
        tool_name: str,
        tool_args: Mapping[str, Any] | None = None,
        *,
        rationale: str | None = None,
        status: Status = Status.OK,
        result_preview: str | None = None,
        error: ErrorInfo | None = None,
        decision: str | None = None,
        latency_ms: float | None = None,
    ) -> AuditEvent:
        """Log a tool execution or denial.

        ``rationale`` defaults to ``tool_args["rationale"]``. It is always moved out of
        ``tool_args`` into its own field. Denied calls are attributed to the agent,
        since the tool never ran.
        """
        args = dict(tool_args or {})
        arg_rationale = args.pop(RATIONALE_KEY, None)
        if rationale is None and isinstance(arg_rationale, str):
            rationale = arg_rationale
        return self.log(
            run_id,
            EventType.TOOL_CALL,
            Actor.AGENT if status is Status.DENIED else Actor.TOOL,
            status=status,
            tool_name=tool_name,
            tool_args=args,
            rationale=rationale,
            result_preview=result_preview,
            error=error,
            decision=decision,
            latency_ms=latency_ms,
        )

    def data_access(
        self,
        run_id: str,
        tool_name: str,
        data_source: str,
        operation: DataOperation,
        *,
        records_touched: int | None = None,
        fields_accessed: list[str] | None = None,
    ) -> AuditEvent:
        return self.log(
            run_id,
            EventType.DATA_ACCESS,
            Actor.TOOL,
            tool_name=tool_name,
            data_source=data_source,
            data_operation=operation,
            records_touched=records_touched,
            fields_accessed=fields_accessed,
        )

    def final_response(
        self,
        run_id: str,
        content: str,
        *,
        model: str | None = None,
        model_explanation: str | None = None,
        latency_ms: float | None = None,
        tokens: TokenUsage | None = None,
    ) -> AuditEvent:
        return self.log(
            run_id,
            EventType.FINAL_RESPONSE,
            Actor.AGENT,
            decision="final_answer",
            content=content,
            model=model,
            model_explanation=model_explanation,
            latency_ms=latency_ms,
            tokens=tokens,
        )

    def error(
        self,
        run_id: str,
        error: ErrorInfo | BaseException,
        *,
        actor: Actor = Actor.SYSTEM,
        tool_name: str | None = None,
        model: str | None = None,
        rationale: str | None = None,
    ) -> AuditEvent:
        info = error if isinstance(error, ErrorInfo) else error_info(error)
        return self.log(
            run_id,
            EventType.ERROR,
            actor,
            status=Status.ERROR,
            error=info,
            tool_name=tool_name,
            model=model,
            rationale=rationale,
        )

    # Internals

    def _peek_step(self, run_id: str) -> int:
        if run_id not in self._next_step:
            last = self._store.last_step_id(run_id)
            self._next_step[run_id] = 0 if last is None else last + 1
        return self._next_step[run_id]

    def _redact_fields(self, fields: Mapping[str, Any]) -> tuple[dict[str, Any], list[str]]:
        out = {key: value for key, value in fields.items() if value is not None}
        tags: set[str] = set()

        def scrub(value: Any) -> Any:
            result = self._redactor.redact(value)
            tags.update(result.tags)
            return result.value

        for name in _TEXT_FIELDS:
            if name in out:
                out[name] = scrub(str(out[name]))
        if "result_preview" in out:
            out["result_preview"] = truncate(out["result_preview"])
        if "tool_args" in out:
            out["tool_args"] = scrub(dict(out["tool_args"]))
        if "error" in out:
            err: ErrorInfo = out["error"]
            out["error"] = ErrorInfo(type=err.type, message=scrub(err.message))
        return out, sorted(tags)

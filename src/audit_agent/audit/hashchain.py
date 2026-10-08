"""Canonical JSON, SHA-256 event hashing, and hash-chain verification.

Hashing rules (``docs/AUDIT_SCHEMA.md``):

* Canonical JSON is ``json.dumps(obj, sort_keys=True, separators=(",", ":"),
  ensure_ascii=False)`` encoded as UTF-8. NaN/Infinity are rejected.
* An event's hash is ``sha256(canonical_json(event_without_hash))``. The hashed object
  includes ``seq`` and ``prev_hash``, so each hash commits to the whole chain before it.
* There is one global chain. ``seq`` starts at 1 and the genesis ``prev_hash`` is 64 zeros.

Verification recomputes every hash in ``seq`` order and checks ``seq`` continuity and
``prev_hash`` linkage, so editing, deleting, inserting, or reordering events is detected.
Truncating the *tail* of the chain, or rewriting the whole chain, is not detectable from
the chain alone; exporting/signing the chain head is backlog work.
"""

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from audit_agent.audit.events import GENESIS_HASH, AuditEvent, AuditEventBody

HASH_FIELD = "hash"


class TamperedRecordError(Exception):
    """A stored record cannot be turned back into a consistent ``AuditEvent``.

    Raised by storage readers (e.g. unparseable payload, or indexed columns that
    disagree with the payload). ``verify_chain`` reports it as a verification failure.
    """

    def __init__(self, seq: int | None, reason: str) -> None:
        super().__init__(f"seq {seq}: {reason}" if seq is not None else reason)
        self.seq = seq
        self.reason = reason


def canonical_json(obj: Any) -> bytes:
    """Deterministic UTF-8 JSON encoding used for hashing and storage."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def compute_hash(payload: Mapping[str, Any]) -> str:
    """SHA-256 hex digest of ``payload`` without its ``hash`` field."""
    unhashed = {key: value for key, value in payload.items() if key != HASH_FIELD}
    return hashlib.sha256(canonical_json(unhashed)).hexdigest()


def event_payload(event: AuditEvent) -> dict[str, Any]:
    """The JSON-ready dict of a full event, exactly as it is stored and hashed."""
    return event.model_dump(mode="json")


def event_hash(event: AuditEvent) -> str:
    """Recompute the hash an event *should* have from its current content."""
    return compute_hash(event_payload(event))


def chain_event(body: AuditEventBody, *, seq: int, prev_hash: str) -> AuditEvent:
    """Attach chain fields to a (redacted) event body and compute its hash."""
    unhashed = body.model_dump(mode="json") | {"seq": seq, "prev_hash": prev_hash}
    return AuditEvent.model_validate(unhashed | {HASH_FIELD: compute_hash(unhashed)})


@dataclass(frozen=True)
class ChainProblem:
    """The first point where verification failed."""

    seq: int | None
    reason: str


@dataclass(frozen=True)
class VerificationResult:
    """Outcome of ``verify_chain``. ``head_hash`` is the hash of the last valid event."""

    ok: bool
    events_checked: int
    head_hash: str
    problem: ChainProblem | None = None


def verify_chain(events: Iterable[AuditEvent]) -> VerificationResult:
    """Verify a full chain supplied in ``seq`` order. Stops at the first problem.

    ``events`` may be a lazy iterator; a ``TamperedRecordError`` raised while iterating
    is reported as a failure rather than propagated.
    """
    expected_seq = 1
    prev_hash = GENESIS_HASH
    checked = 0

    def fail(seq: int | None, reason: str) -> VerificationResult:
        return VerificationResult(False, checked, prev_hash, ChainProblem(seq, reason))

    iterator = iter(events)
    while True:
        try:
            event = next(iterator)
        except StopIteration:
            break
        except TamperedRecordError as exc:
            return fail(exc.seq, exc.reason)

        if event.seq != expected_seq:
            return fail(event.seq, f"expected seq {expected_seq}, found {event.seq}")
        if event.prev_hash != prev_hash:
            return fail(event.seq, "prev_hash does not match the previous event's hash")
        if event_hash(event) != event.hash:
            return fail(event.seq, "hash mismatch: event content was modified")

        prev_hash = event.hash
        expected_seq += 1
        checked += 1

    return VerificationResult(True, checked, prev_hash)

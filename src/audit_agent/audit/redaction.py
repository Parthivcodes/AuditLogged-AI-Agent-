"""Redaction of secrets and PII. This is the only module that contains redaction logic.

Everything bound for the audit log goes through a ``Redactor`` before it is hashed
or stored. There are two detection mechanisms:

* **Value patterns**: regexes for API keys, bearer tokens, AWS keys, credit cards
  (Luhn-checked), emails, phone numbers, ``key=value`` secrets, and exact literal
  secrets such as the configured API key.
* **Key names**: dict values under sensitive keys (``password``, ``api_key``,
  ``customer_email``, ...) are masked whole, whatever they look like.

How a detected value is replaced is a pluggable ``ReplacementStrategy``. v1 uses
``mask_strategy``, which produces ``[REDACTED:<kind>]``. A salted-hash token strategy
can be added later without changing callers.

Known limitation: free-text PII with no recognizable shape, such as a person's name
inside a sentence, is not detected. Structured data should carry such values under
PII key names so they are masked by key.
"""

import json
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

SECRET = "secret"
PII = "pii"


class ReplacementStrategy(Protocol):
    """Turns a detected sensitive value into its logged replacement."""

    def __call__(self, kind: str, original: str) -> str: ...


def mask_strategy(kind: str, original: str) -> str:
    """v1 strategy: an irreversible mask that keeps only the kind of value."""
    return f"[REDACTED:{kind}]"


@dataclass(frozen=True)
class Pattern:
    """A value-detection rule.

    If ``regex`` defines a named group ``v``, only that group is replaced, so
    surrounding context such as ``password=`` or ``Bearer`` stays readable.
    ``validator`` can reject false positives (e.g. a Luhn check for card numbers).
    """

    kind: str
    regex: re.Pattern[str]
    validator: Callable[[str], bool] | None = None


@dataclass(frozen=True)
class Redacted:
    """Result of redaction: the cleaned value and the sorted, unique kinds removed."""

    value: Any
    tags: tuple[str, ...]

    @property
    def changed(self) -> bool:
        return bool(self.tags)


def luhn_valid(candidate: str) -> bool:
    """True if the digits in ``candidate`` form a 13–19 digit Luhn-valid number."""
    digits = [int(c) for c in candidate if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    for index, digit in enumerate(reversed(digits)):
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


_PHONE_REGEX = r"""
(?<![\w+])
(?:
    \+\d{1,3}[\s.-]?\d{4,5}[\s.-]?\d{5,6}                       # +91 98765 43210
  | (?:\+\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)\s?|\d{2,5}[\s.-])\d{3,5}[\s.-]\d{4}
                                                              # (555) 123-4567, +1 555 123 4567
  | \+\d{10,15}                                               # +15551234567
)
(?!\w)
"""

_SECRET_WORDS = (
    r"password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key"
    r"|authorization|credentials?"
)

DEFAULT_PATTERNS: tuple[Pattern, ...] = (
    Pattern("anthropic_key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{8,}")),
    Pattern("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}")),
    Pattern("bearer_token", re.compile(r"(?i)\bbearer\s+(?P<v>[A-Za-z0-9\-._~+/]{8,}=*)")),
    Pattern("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    Pattern("credit_card", re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"), luhn_valid),
    Pattern(
        "email",
        re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}"),
    ),
    Pattern("phone", re.compile(_PHONE_REGEX, re.VERBOSE)),
    Pattern(
        SECRET,
        re.compile(
            rf"(?i)(?<![A-Za-z0-9])(?:{_SECRET_WORDS})(?![A-Za-z0-9])"
            r"[\"']?\s*[:=]\s*[\"']?(?!\[REDACTED:)(?!bearer\b)(?P<v>[^\s,;'\"]+)"
        ),
    ),
)

# Key names are compared after lowercasing and removing non-alphanumerics,
# so "API-Key", "api_key" and "apiKey" all normalize to "apikey".
DEFAULT_SECRET_KEYS: frozenset[str] = frozenset(
    {
        "password", "passwd", "pwd", "secret", "token", "apikey", "xapikey",
        "authorization", "credential", "credentials", "privatekey", "accesskey",
        "cookie", "setcookie", "sessionid",
    }
)  # fmt: skip
DEFAULT_SECRET_KEY_SUFFIXES: tuple[str, ...] = (
    "password", "secret", "token", "apikey", "privatekey", "accesskey", "credential",
    "credentials",
)  # fmt: skip
DEFAULT_PII_KEYS: frozenset[str] = frozenset(
    {
        "fullname", "firstname", "lastname", "customername", "contactname",
        "email", "emailaddress", "phone", "phonenumber", "mobile",
        "address", "streetaddress", "ssn", "dateofbirth", "dob",
    }
)  # fmt: skip
DEFAULT_PII_KEY_SUFFIXES: tuple[str, ...] = ("email", "phone", "phonenumber", "ssn")

_MIN_LITERAL_LENGTH = 8


def normalize_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key.lower())


def _stringify(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, default=str)


class Redactor:
    """Recursively redacts strings, dicts, lists, and tuples. Never mutates its input."""

    def __init__(
        self,
        *,
        patterns: Iterable[Pattern] = DEFAULT_PATTERNS,
        secret_keys: Iterable[str] = DEFAULT_SECRET_KEYS,
        secret_key_suffixes: Iterable[str] = DEFAULT_SECRET_KEY_SUFFIXES,
        pii_keys: Iterable[str] = DEFAULT_PII_KEYS,
        pii_key_suffixes: Iterable[str] = DEFAULT_PII_KEY_SUFFIXES,
        literal_secrets: Iterable[str] = (),
        strategy: ReplacementStrategy = mask_strategy,
    ) -> None:
        literals = sorted(
            {s for s in literal_secrets if s and len(s) >= _MIN_LITERAL_LENGTH},
            key=len,
            reverse=True,
        )
        literal_patterns: tuple[Pattern, ...] = (
            (Pattern(SECRET, re.compile("|".join(map(re.escape, literals)))),) if literals else ()
        )
        self._patterns = literal_patterns + tuple(patterns)
        self._secret_keys = frozenset(normalize_key(k) for k in secret_keys)
        self._secret_suffixes = tuple(normalize_key(s) for s in secret_key_suffixes)
        self._pii_keys = frozenset(normalize_key(k) for k in pii_keys)
        self._pii_suffixes = tuple(normalize_key(s) for s in pii_key_suffixes)
        self._strategy = strategy

    # Public API

    def redact(self, value: Any) -> Redacted:
        """Return a redacted copy of ``value`` and the kinds of data removed."""
        tags: set[str] = set()
        cleaned = self._redact_value(value, tags)
        return Redacted(value=cleaned, tags=tuple(sorted(tags)))

    def sensitive_key_kind(self, key: str) -> str | None:
        """``"secret"``, ``"pii"``, or ``None`` for a dict key name."""
        norm = normalize_key(key)
        if not norm:
            return None
        if norm in self._secret_keys or norm.endswith(self._secret_suffixes):
            return SECRET
        if norm in self._pii_keys or norm.endswith(self._pii_suffixes):
            return PII
        return None

    # Internals

    def _redact_value(self, value: Any, tags: set[str]) -> Any:
        if value is None or isinstance(value, bool | int | float):
            return value
        if isinstance(value, str):
            return self._redact_str(value, tags)
        if isinstance(value, Mapping):
            return self._redact_mapping(value, tags)
        if isinstance(value, set | frozenset):
            return [self._redact_value(v, tags) for v in sorted(value, key=repr)]
        if isinstance(value, list | tuple):
            return [self._redact_value(v, tags) for v in value]
        # Unknown objects could hide sensitive data in their repr. Log them as redacted text.
        return self._redact_str(str(value), tags)

    def _redact_mapping(self, mapping: Mapping[Any, Any], tags: set[str]) -> dict[Any, Any]:
        out: dict[Any, Any] = {}
        for key, val in mapping.items():
            kind = self.sensitive_key_kind(key) if isinstance(key, str) else None
            new_key = self._redact_str(key, tags) if isinstance(key, str) else key
            if new_key in out:  # e.g. two different emails used as keys
                suffix = 2
                while f"{new_key}#{suffix}" in out:
                    suffix += 1
                new_key = f"{new_key}#{suffix}"
            if kind is not None and val not in (None, ""):
                tags.add(kind)
                out[new_key] = self._strategy(kind, _stringify(val))
            else:
                out[new_key] = self._redact_value(val, tags)
        return out

    def _redact_str(self, text: str, tags: set[str]) -> str:
        for pattern in self._patterns:
            text = pattern.regex.sub(lambda m, p=pattern: self._replace(m, p, tags), text)
        return text

    def _replace(self, match: re.Match[str], pattern: Pattern, tags: set[str]) -> str:
        has_group = "v" in pattern.regex.groupindex
        secret = match.group("v") if has_group else match.group(0)
        if pattern.validator is not None and not pattern.validator(secret):
            return match.group(0)
        tags.add(pattern.kind)
        replacement = self._strategy(pattern.kind, secret)
        if not has_group:
            return replacement
        whole, offset = match.group(0), match.start()
        start, end = match.span("v")
        return whole[: start - offset] + replacement + whole[end - offset :]


_default_redactor = Redactor()


def redact(value: Any) -> Redacted:
    """Redact ``value`` with the default rules (no literal secrets configured)."""
    return _default_redactor.redact(value)

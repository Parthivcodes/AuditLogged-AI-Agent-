"""Tests for audit/redaction.py: secrets and PII must never survive redaction."""

import pytest

from audit_agent.audit.redaction import Redactor, luhn_valid, redact

# Value patterns in free text


@pytest.mark.parametrize(
    ("text", "secret", "tag"),
    [
        (
            "key is sk-ant-api03-AbCdEf123456_xyz-789",
            "sk-ant-api03-AbCdEf123456_xyz-789",
            "anthropic_key",
        ),
        (
            "openai sk-proj-abcdefghijklmnopqrstuvwxyz123",
            "sk-proj-abcdefghijklmnopqrstuvwxyz123",
            "openai_key",
        ),
        ("aws AKIAIOSFODNN7EXAMPLE used", "AKIAIOSFODNN7EXAMPLE", "aws_access_key"),
        ("contact alice.smith+q1@example.co.uk now", "alice.smith+q1@example.co.uk", "email"),
        ("card 4111 1111 1111 1111 on file", "4111 1111 1111 1111", "credit_card"),
        ("card 4111-1111-1111-1111 on file", "4111-1111-1111-1111", "credit_card"),
        ("card 5500000000000004 on file", "5500000000000004", "credit_card"),
    ],
)
def test_value_patterns_are_masked(text: str, secret: str, tag: str) -> None:
    result = redact(text)
    assert secret not in result.value
    assert f"[REDACTED:{tag}]" in result.value
    assert tag in result.tags


@pytest.mark.parametrize(
    "phone",
    [
        "555-123-4567",
        "(555) 123-4567",
        "555.123.4567",
        "+1 555 123 4567",
        "+91 98765 43210",
        "+15551234567",
    ],
)
def test_phone_numbers_are_masked(phone: str) -> None:
    result = redact(f"call {phone} today")
    assert phone not in result.value
    assert result.value == "call [REDACTED:phone] today"
    assert result.tags == ("phone",)


def test_bearer_token_keeps_scheme_but_masks_token() -> None:
    result = redact("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig")
    assert "eyJhbGciOiJIUzI1NiJ9" not in result.value
    assert result.value == "Authorization: Bearer [REDACTED:bearer_token]"
    assert result.tags == ("bearer_token",)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("password=hunter22", "password=[REDACTED:secret]"),
        ("db_password: hunter22", "db_password: [REDACTED:secret]"),
        ('{"api_key": "abc123xyz"}', '{"api_key": "[REDACTED:secret]"}'),
        ("token = abc.def.ghi", "token = [REDACTED:secret]"),
    ],
)
def test_key_value_secrets_in_text(text: str, expected: str) -> None:
    result = redact(text)
    assert result.value == expected
    assert result.tags == ("secret",)


@pytest.mark.parametrize(
    "text",
    [
        "Q1 revenue was $482,310.50 across 60 orders",
        "order_id 1001 shipped on 2026-03-31T10:33:12.481Z",
        "server 192.168.1.100 port 8000",
        "units=42 region=North",
        "max_tokens=1024 and tokens: 812",
        "card-like but Luhn-invalid 4111111111111112",
        "Widget,10,25.00,250.00",
    ],
)
def test_benign_text_is_untouched(text: str) -> None:
    result = redact(text)
    assert result.value == text
    assert result.tags == ()
    assert not result.changed


def test_sample_csv_row_masks_email_but_keeps_numbers() -> None:
    row = "1001,2026-01-05,North,Widget,10,25.00,250.00,Alice Smith,alice@example.com"
    result = redact(row)
    assert (
        result.value == "1001,2026-01-05,North,Widget,10,25.00,250.00,Alice Smith,[REDACTED:email]"
    )
    assert result.tags == ("email",)


# Structured data and key names


def test_sensitive_keys_are_masked_whole() -> None:
    args = {
        "password": "x",
        "API-Key": "not-a-recognizable-shape",
        "nested": {"client_secret": {"deep": "value"}, "refresh_token": 12345},
        "headers": {"Authorization": "Basic dXNlcjpwYXNz"},
        "dataset": "sales_q1",
    }
    result = redact(args)
    assert result.value == {
        "password": "[REDACTED:secret]",
        "API-Key": "[REDACTED:secret]",
        "nested": {"client_secret": "[REDACTED:secret]", "refresh_token": "[REDACTED:secret]"},
        "headers": {"Authorization": "[REDACTED:secret]"},
        "dataset": "sales_q1",
    }
    assert result.tags == ("secret",)


def test_pii_keys_are_masked_whole() -> None:
    row = {
        "order_id": 1001,
        "customer_name": "Alice Smith",
        "customer_email": "a@x.com",
        "revenue": 250.0,
    }
    result = redact(row)
    assert result.value == {
        "order_id": 1001,
        "customer_name": "[REDACTED:pii]",
        "customer_email": "[REDACTED:pii]",
        "revenue": 250.0,
    }
    assert result.tags == ("pii",)


def test_non_sensitive_lookalike_keys_are_not_masked() -> None:
    args = {
        "max_tokens": 1024,
        "filename": "q1.md",
        "tool_name": "read_sales_data",
        "dataset_name": "q1",
    }
    assert redact(args).value == args


def test_empty_sensitive_values_are_left_alone() -> None:
    result = redact({"password": None, "token": ""})
    assert result.value == {"password": None, "token": ""}
    assert result.tags == ()


def test_recurses_into_lists_tuples_and_sets() -> None:
    value = {"rows": [{"email": "a@x.com"}, ("call 555-123-4567",)], "tags": {"b@y.com"}}
    result = redact(value)
    assert result.value == {
        "rows": [{"email": "[REDACTED:pii]"}, ["call [REDACTED:phone]"]],
        "tags": ["[REDACTED:email]"],
    }
    assert result.tags == ("email", "phone", "pii")


def test_scalars_are_preserved() -> None:
    value = {"n": 3, "f": 1.5, "b": True, "none": None}
    assert redact(value).value == value


def test_unknown_objects_are_stringified_and_redacted() -> None:
    class Customer:
        def __str__(self) -> str:
            return "Customer(alice@example.com)"

    result = redact({"obj": Customer()})
    assert result.value == {"obj": "Customer([REDACTED:email])"}


def test_dict_keys_containing_pii_are_redacted_without_collisions() -> None:
    result = redact({"a@x.com": 1, "b@y.com": 2})
    assert result.value == {"[REDACTED:email]": 1, "[REDACTED:email]#2": 2}


def test_input_is_not_mutated() -> None:
    original = {"password": "pw", "rows": [{"email": "a@x.com"}]}
    snapshot = {"password": "pw", "rows": [{"email": "a@x.com"}]}
    redact(original)
    assert original == snapshot


def test_redaction_is_idempotent() -> None:
    value = {"note": "mail a@x.com, key sk-ant-api03-abcdefgh123, Bearer abcdefghijkl", "pwd": "x"}
    once = redact(value)
    twice = redact(once.value)
    assert twice.value == once.value


def test_tags_are_sorted_and_unique() -> None:
    result = redact(["a@x.com", "b@y.com", "555-123-4567", {"token": "t"}])
    assert result.tags == ("email", "phone", "secret")


# Configuration and strategy hook


def test_literal_secrets_are_masked() -> None:
    redactor = Redactor(literal_secrets=["my-very-own-secret-value", "short"])
    result = redactor.redact("value my-very-own-secret-value and short")
    assert result.value == "value [REDACTED:secret] and short"
    assert result.tags == ("secret",)


def test_custom_strategy_hook_for_future_hashed_tokens() -> None:
    redactor = Redactor(strategy=lambda kind, original: f"<{kind}:{len(original)}>")
    result = redactor.redact({"note": "mail a@x.com", "password": "hunter22"})
    assert result.value == {"note": "mail <email:7>", "password": "<secret:8>"}


def test_sensitive_key_kind() -> None:
    redactor = Redactor()
    assert redactor.sensitive_key_kind("X-Api-Key") == "secret"
    assert redactor.sensitive_key_kind("contact_email") == "pii"
    assert redactor.sensitive_key_kind("region") is None
    assert redactor.sensitive_key_kind("__") is None


@pytest.mark.parametrize(
    ("number", "valid"),
    [
        ("4111111111111111", True),
        ("4111 1111 1111 1112", False),
        ("1234", False),
        ("79927398713", False),
    ],
)
def test_luhn_valid(number: str, valid: bool) -> None:
    assert luhn_valid(number) is valid

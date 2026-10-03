import pytest

from prompt_privacy.core.types import EntityType as T
from prompt_privacy.detectors.base import detect


def types(text: str, **kw: bool) -> list[tuple[str, str]]:
    return [(f.type.value, f.value) for f in detect(text, **kw)]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("NRIC S1234567D.", [("NRIC", "S1234567D")]),
        ("card 4111 1111 1111 1111", [("CARD", "4111 1111 1111 1111")]),
        ("amex 3782 822463 10005", [("CARD", "3782 822463 10005")]),
        ("iban GB82 WEST 1234 5698 7654 32", [("IBAN", "GB82 WEST 1234 5698 7654 32")]),
        ("mail jane.tan@acme-corp.test", [("EMAIL", "jane.tan@acme-corp.test")]),
        ("call +65 9123 4567", [("PHONE", "+65 9123 4567")]),
        ("phone (415) 555-0123", [("PHONE", "(415) 555-0123")]),
        ("host 192.0.2.10 and 2001:db8::1", [("IPV4", "192.0.2.10"), ("IPV6", "2001:db8::1")]),
    ],
)
def test_positives(text: str, expected: list[tuple[str, str]]) -> None:
    assert types(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        "Ticket 418019 opened 2026-10-04 14:31.",
        "ISBN 978-0-655-72619-2",
        "invalid S1234567A",
        "card-like 4111111111111112",
        "commit 04745b79e1a6536850706174b8bec09",
        "version 1.4.76, address 999.1.2.3",
    ],
)
def test_hard_negatives(text: str) -> None:
    assert types(text) == []


def test_phone_context_setting() -> None:
    assert types("order 8947-4680") == [("PHONE", "8947-4680")]  # optional: recall first
    assert types("order 8947-4680", phone_context=True) == []
    assert types("call 8947-4680", phone_context=True) == [("PHONE", "8947-4680")]


@pytest.mark.parametrize("text", ["S12\u200b34567D", "Ｓ１２３４５６７Ｄ", "S\u200d1234567D"])
def test_evasion_folded(text: str) -> None:
    fs = detect(f"id {text} ok")
    assert [f.type for f in fs] == [T.NRIC]
    assert fs[0].value == text  # offsets map back to the original characters


def test_secrets() -> None:
    text = (
        "AKIAIOSFODNN7EXAMPLE ghp_" + "a" * 36 + "\nexport API_KEY=abcd1234efgh5678\n"
        "postgres://app:s3cr3tpass@db.internal/x\n"
        "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----"
    )
    subtypes = [f.subtype for f in detect(text) if f.type is T.SECRET]
    assert subtypes == [
        "aws_access_key_id",
        "github_token",
        "assignment",
        "url_credentials",
        "private_key_block",
    ]

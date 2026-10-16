"""Cross-check of PPE's check-digit code against an independent implementation, python-stdnum.

python-stdnum (LGPL-2.1+) is a test-only dependency; PPE does not ship or import it. It has no
Singapore NRIC/FIN module (2.2 has `sg.uen` only), so NRIC has no independent reference here.
"""

import random
import re
import string

import pytest
from hypothesis import given
from hypothesis import strategies as st

from prompt_privacy.core.checksums import iban_check_digits, iban_valid, luhn_check_digit, luhn_valid
from prompt_privacy.core.keys import TokenKey
from prompt_privacy.core.surrogates import Surrogator
from prompt_privacy.core.types import EntityType
from prompt_privacy.corpus.generator import Generator
from prompt_privacy.detectors.base import detect

stdnum = pytest.importorskip("stdnum")
from stdnum import iban as std_iban  # noqa: E402
from stdnum import luhn as std_luhn  # noqa: E402

_CHARS = {"n": string.digits, "a": string.ascii_uppercase, "c": string.ascii_uppercase + string.digits}


def _registry() -> list[tuple[str, str]]:
    """(country, BBAN structure such as '4!a6!n8!n') for every country stdnum knows."""
    out = []
    for cc in (a + b for a in string.ascii_uppercase for b in string.ascii_uppercase):
        info = std_iban._ibandb.info(cc)
        if info and info[0][1].get("bban"):
            out.append((cc, info[0][1]["bban"]))
    return out


REGISTRY = _registry()


def _bban(r: random.Random, structure: str) -> str:
    return "".join(
        "".join(r.choice(_CHARS[kind]) for _ in range(int(n)))
        for n, kind in re.findall(r"(\d+)!([nac])", structure)
    )


def test_registry_is_not_empty() -> None:
    assert len(REGISTRY) >= 80  # stdnum 2.2: 89 countries


@given(st.text(alphabet=string.digits, min_size=2, max_size=25))
def test_luhn_agrees(digits: str) -> None:
    assert luhn_valid(digits) == std_luhn.is_valid(digits)


@given(st.text(alphabet=string.digits, min_size=1, max_size=24))
def test_luhn_check_digit_agrees(payload: str) -> None:
    assert str(luhn_check_digit(payload)) == std_luhn.calc_check_digit(payload)


def test_every_stdnum_valid_iban_is_valid_and_detected() -> None:
    """For every registry country: PPE's check digits equal stdnum's, and every IBAN stdnum accepts is
    accepted by `iban_valid` and found by `detect` in compact and in printed (grouped) form."""
    r = random.Random(20261016)  # noqa: S311 — synthetic test data
    countries_checked = 0
    for cc, structure in REGISTRY:
        accepted = 0
        for _ in range(8):
            bban = _bban(r, structure)
            check = iban_check_digits(cc, bban)
            assert check == std_iban.calc_check_digits(cc + "00" + bban), cc
            value = cc + check + bban
            if not std_iban.is_valid(value):  # some countries add a national check stdnum also verifies
                continue
            accepted += 1
            assert iban_valid(value), value
            for form in (value, std_iban.format(value)):
                found = detect(f"Pay to {form}.")
                assert [(f.type, f.value) for f in found] == [(EntityType.IBAN, form)], (cc, form)
        countries_checked += accepted > 0
    assert countries_checked >= 0.8 * len(REGISTRY)


@pytest.mark.xfail(
    strict=True,
    reason="known gap: iban_valid checks ISO 7064 mod 97-10 and a 15-34 length only, not the per-country "
    "length and BBAN layout (Nemotron-PII run 2026-10-16: 16 IBAN findings, 5 on account numbers)",
)
def test_iban_rejects_what_the_registry_rejects() -> None:
    r = random.Random(7)  # noqa: S311 — synthetic test data
    for _ in range(200):
        cc = "".join(r.choice(string.ascii_uppercase) for _ in range(2))
        bban = "".join(r.choice(_CHARS["c"]) for _ in range(r.randint(11, 30)))
        value = cc + iban_check_digits(cc, bban) + bban
        assert iban_valid(value) == std_iban.is_valid(value)


def test_corpus_values_are_valid_for_stdnum() -> None:
    g = Generator(20261016)
    for _ in range(500):
        assert std_iban.is_valid(g.iban())
        assert std_luhn.is_valid(g.card())


def test_surrogates_are_invalid_for_stdnum() -> None:
    """G2 (ADR-0008): card and IBAN surrogates carry a check digit an independent validator rejects."""
    g = Generator(5)
    factory = Surrogator(TokenKey(b"\x01" * 32))
    for i in range(500):
        iban, card = g.iban(), g.card()
        assert not std_iban.is_valid(factory.make(f"c{i}", EntityType.IBAN, iban).canonical)
        assert not std_luhn.is_valid(factory.make(f"c{i}", EntityType.CARD, card).canonical)

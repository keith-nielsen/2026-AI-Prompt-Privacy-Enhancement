"""Conformance: detection, surrogates, swap and restore, checked against what the docs claim.

Each test names the claim (C-nn, see docs/review/2026-10-16-product-review.md) and its source. Claims the
code does not meet yet are `xfail(strict=True)` with the review finding id (F-nn): the suite stays green,
documents the gap, and turns red when the gap is fixed so the marker can be removed. Synthetic data only.
"""

from __future__ import annotations

import json
import random

import pytest

from prompt_privacy.core.checksums import (
    iban_check_digits,
    iban_valid,
    luhn_valid,
    nric_check_letter,
    nric_valid,
)
from prompt_privacy.core.engine import Engine, Message
from prompt_privacy.core.keys import TokenKey
from prompt_privacy.core.normalise import norm
from prompt_privacy.core.surrogates import Guarantee, Surrogate, Surrogator
from prompt_privacy.core.types import EntityType as T
from prompt_privacy.detectors import gitleaks
from prompt_privacy.detectors.base import Dictionary, detect
from prompt_privacy.detectors.secrets import SECRET_RULES

KEY = TokenKey(bytes(range(32)))


def _entry(res, etype):  # type: ignore[no-untyped-def]
    return next(e for (t, _), e in res.vault.entries.items() if t is etype)


# --- detection ---------------------------------------------------------------------------------


def test_c01_stage0_folds_fullwidth_zero_width_and_bidi() -> None:
    """C-01 (README status): Stage 0 folds full-width digits, zero-width and bidi characters."""
    for text in (
        "S123\u200b4567D",
        "\uff33\uff11\uff12\uff13\uff14\uff15\uff16\uff17\uff24",
        "S1234\u202e567D",
    ):
        assert [f.type for f in detect(text)] == [T.NRIC], text


def test_c03_twelve_secret_rules() -> None:
    """C-03 (README 'Built and designed'): 15 PPE secret rules plus 217 imported Gitleaks 8.30.1 rules."""
    assert len(SECRET_RULES) == 15
    assert len(gitleaks.rule_set().rules) == 217


def test_c04_nric_fin_check_letters_known_answers() -> None:
    """C-04 (README: checksums incl. SG NRIC/FIN M-series). Known-answer vectors from outside this repo:
    S1234567D (widely published sample), M1235467X (samliew/singapore-nric README, an independent
    implementation). The repo's own series test is circular (mutant M01 survived the review)."""
    assert nric_valid("S1234567D") and nric_valid("M1235467X")
    assert nric_check_letter("M", "1235467") == "X"


def test_c04_iban_rejects_remainder_zero() -> None:
    """C-04: an IBAN is valid only when mod-97 == 1 (ISO 13616); remainder 0 must fail (mutant M03)."""
    bban = "WEST12345698765432"
    good = int(iban_check_digits("GB", bban))
    assert iban_valid(f"GB{good:02d}{bban}")
    assert not iban_valid(f"GB{good - 1:02d}{bban}")  # remainder 0


@pytest.mark.xfail(
    strict=True, reason="F-21: isdigit() accepts superscripts that int() rejects -> ValueError"
)
def test_c04_checksums_return_false_on_non_ascii_digits() -> None:
    """C-04 robustness: validators return False (not raise) on odd input."""
    assert nric_valid("S\u00b2234567D") is False
    assert luhn_valid("41\u00b2") is False


_CODE = {
    "rust use": "use std::io::{self, Read};",
    "cpp scope": "std::string s = ns::util::join(parts);",
    "ruby const": "Foo::Bar::Baz.new",
    "css pseudo": "a::before { content: ''; }",
    "py classifier": "Development Status :: 4 - Beta",
    "py token var": "token = get_token(request)",
    "py password field": "password = form.cleaned_data['password']",
    "py env lookup": "API_KEY = os.environ['API_KEY']",
    "imei": "IMEI 490154203237518",
    "ssh algorithm": "PubkeyAcceptedAlgorithms sk-ssh-ed25519@openssh.com",
}


# Fixed 2026-10-16 (IPv6 not inside a word, found on the Gretel finance run): the four `::` cases
# joined to words. Fixed 2026-10-18 (assignment values with a Gitleaks placeholder word dropped): the
# two placeholder assignment cases. Fixed 2026-10-18 (secret rules v3: code references dropped): the
# environment lookup. Still open under F-02: a bare `::`, IMEI, an ssh algorithm name.
_C07_FIXED = {
    "rust use",
    "cpp scope",
    "ruby const",
    "css pseudo",
    "py password field",
    "py token var",
    "py env lookup",
}
_C07_OPEN = pytest.mark.xfail(
    strict=True, reason="F-02: Stage 1 false positives on source code (bare '::', IMEI, ssh algorithm name)"
)


@pytest.mark.parametrize(
    "name", [n if n in _C07_FIXED else pytest.param(n, marks=_C07_OPEN) for n in sorted(_CODE)]
)
def test_c07_ordinary_code_has_no_findings(name: str) -> None:
    """C-07 (PLAN §1: coding CLIs/IDEs/agents are the main audience): ordinary code is not an identifier."""
    assert detect(_CODE[name]) == []


def test_c08_random_ids_rarely_look_like_cards() -> None:
    """C-08 (ADR-0005: cards = Luhn + IIN ranges). Measures the Luhn-only false-positive rate on random
    16-digit ids; ~10 % is what Luhn alone gives. Kept as a measurement (passes), threshold documents it."""
    rng = random.Random(1)  # noqa: S311 — reproducible measurement, not secrecy
    ids = ["".join(str(rng.randint(0, 9)) for _ in range(16)) for _ in range(5000)]
    rate = sum(any(f.type is T.CARD for f in detect(f"order {i}")) for i in ids) / len(ids)
    assert 0.08 < rate < 0.12  # F-02: no IIN/context check; a fix should drive this toward 0


@pytest.mark.xfail(
    strict=True, reason="F-15: IPv4-mapped IPv6 detected as '::ffff:192', 3 octets stay in clear"
)
def test_c09_masking_never_leaves_part_of_an_identifier() -> None:
    """C-09 (threat model §1 security objective): no identifier leaves in clear, not even partly."""
    out = Engine(KEY).mask([Message("user", "peer ::ffff:192.0.2.10 connected")], "c").messages[0].text
    assert "0.2.10" not in out


_EVASIONS = {
    "homoglyph (Cyrillic S)": "id \u04051234567D",
    "spaced digits": "id S 1 2 3 4 5 6 7 D",
    "percent-encoded e-mail": "q=jane.tan%40acme-corp.test",
    "HTML-entity e-mail": "jane.tan&#64;acme-corp.test",
    "card with dots": "card 4111.1111.1111.1111",
}


@pytest.mark.parametrize("name", sorted(_EVASIONS))
@pytest.mark.xfail(
    strict=True, reason="F-15: ADR-0005 Stage 0 confusables/de-spacing/decoding designed, not built"
)
def test_c10_stage0_design_evasions_detected(name: str) -> None:
    """C-10 (ADR-0005 Stage 0 design; threat model 'largest residual')."""
    assert detect(_EVASIONS[name]) != []


# --- surrogates ----------------------------------------------------------------------------------


def test_c11_surrogate_guarantees_for_every_constructed_type() -> None:
    """C-11 (ADR-0008): G2 fail their checksum; G1 sit in reserved ranges (incl. NANP/UK phones)."""
    s = Surrogator(KEY)
    for i in range(200):
        sc = f"s{i}"
        assert not nric_valid(s.make(sc, T.NRIC, "S1234567D").canonical)
        assert not luhn_valid(s.make(sc, T.CARD, "4111111111111111").canonical)
        assert not iban_valid(s.make(sc, T.IBAN, "GB82WEST12345698765432").canonical)
        assert s.make(sc, T.EMAIL, "a@acme-corp.test").canonical.split("@")[1] in (
            "example.com",
            "example.net",
            "example.org",
        )
        nanp = s.make(sc, T.PHONE, "+1 415 555 2671").canonical
        assert nanp.startswith("+1") and nanp[-7:-2] == "55501"
        uk = s.make(sc, T.PHONE, "07911 123456").canonical
        assert uk.startswith("07700900")
        assert s.make(sc, T.SECRET, "AKIAIOSFODNN7ABCDEFG").canonical.endswith("EXAMPLE")


def test_c12_surrogate_never_equals_a_real_value_in_the_request(monkeypatch: pytest.MonkeyPatch) -> None:
    """C-12 (ADR-0008 risk 1 / vault): if a construction collides with a real value, the vault probes on
    (mutant M10 survived the review: nothing tested this)."""
    real_a, real_b = "S1234567D", "T9119134I"
    original = Surrogator.make

    def colliding(self: Surrogator, scope: str, etype: T, value: str, attempt: int = 0) -> Surrogate:
        if attempt == 0 and value == real_a:
            return Surrogate(etype, real_b, Guarantee.G2)  # equals the other real value in the request
        return original(self, scope, etype, value, attempt)

    monkeypatch.setattr(Surrogator, "make", colliding)
    res = Engine(KEY).mask([Message("user", f"ids {real_a} and {real_b}")], "c")
    surs = {e.surrogate.canonical for e in res.vault.entries.values()}
    assert real_a not in surs and real_b not in surs


def test_c13_stable_within_and_unlinkable_across_conversations() -> None:
    """C-13 (ADR-0002 context 2-3)."""
    eng = Engine(KEY)
    text = "NRIC S1234567D mail jane.tan@acme-corp.test"
    a1 = eng.mask([Message("user", text)], "conv-A").messages[0].text
    a2 = eng.mask([Message("user", text), Message("assistant", "ok"), Message("user", "more")], "conv-A")
    b = eng.mask([Message("user", text)], "conv-B").messages[0].text
    assert a1 == a2.messages[0].text and a1 != b


@pytest.mark.xfail(
    strict=True, reason="F-10: vault probes against all conversation text, incl. assistant text"
)
def test_c14_surrogate_stable_when_its_literal_is_in_history() -> None:
    """C-14 (ADR-0002 'byte for byte'; ADR-0008 determinism): one restore miss must not re-key a value."""
    eng = Engine(KEY)
    first = eng.mask([Message("user", "NRIC S1234567D")], "c")
    sur = _entry(first, T.NRIC).surrogate.canonical
    hist = [
        Message("user", "NRIC S1234567D"),
        Message("assistant", f"Noted {sur}."),
        Message("user", "S1234567D?"),
    ]
    again = eng.mask(hist, "c")
    assert again.messages[0].text == first.messages[0].text


# --- restore ----------------------------------------------------------------------------------------


def test_c15_restore_is_closed_world() -> None:
    """C-15 (ADR-0002 R1 / invariant 4): foreign tokens and surrogates are left alone and counted."""
    eng = Engine(KEY, form="token")
    res = eng.mask([Message("user", "card 4111 1111 1111 1111")], "c")
    out = eng.restore("see <CARD_aaaaaaaaaa> and <NRIC_bbbbbbbbbb>", res.vault)
    assert out.restored == 0 and out.misses == 2


def test_c16_token_type_label_must_match() -> None:
    """C-16 (ADR-0002 R2): case of TYPE may change, but a suffix under the wrong TYPE is not restored
    (mutant M09 survived the review)."""
    eng = Engine(KEY, form="token")
    res = eng.mask([Message("user", "card 4111 1111 1111 1111")], "c")
    tok = _entry(res, T.CARD).surrogate.canonical  # <CARD_xxxxxxxxxx>
    suffix = tok[1:-1].split("_", 1)[1]
    out = eng.restore(f"<NRIC_{suffix}> and <card_{suffix}>", res.vault)
    assert out.text.count("4111 1111 1111 1111") == 1 and out.misses == 1


def test_c17_r3_holds_when_the_model_writes_its_own_identifiers() -> None:
    """C-17 (ADR-0002 R3): provider bytes come back unchanged even when the model itself wrote
    identifier-shaped text (no fresh detection on assistant turns; mutant M08 survived the review)."""
    eng = Engine(KEY)
    user = [Message("user", "NRIC S1234567D")]
    res = eng.mask(user, "c")
    sur = _entry(res, T.NRIC).surrogate.canonical
    reply = f"{sur} noted. Example of another format: T9119134I, contact help@acme-corp.test."
    restored = eng.restore(reply, res.vault).text
    again = eng.mask([*user, Message("assistant", restored)], "c")
    assert again.messages[1].text == reply


@pytest.mark.xfail(
    strict=True, reason="F-09: restore is not JSON-aware; escaped values are silently not restored"
)
def test_c18_restore_into_json_tool_arguments() -> None:
    """C-18 (README: originals restored 'including ... tool-call arguments'; ADR-0002 R4)."""
    pem = "-----BEGIN PRIVATE KEY-----\nMIIBVwIBADANBgkqhkiG9w0BAQEFAASCexample\n-----END PRIVATE KEY-----"
    eng = Engine(KEY)
    res = eng.mask([Message("user", "use this key:\n" + pem)], "c")
    sur = _entry(res, T.SECRET).surrogate.canonical
    args = eng.restore(json.dumps({"key": sur}), res.vault).text
    assert json.loads(args)["key"] == pem


@pytest.mark.xfail(strict=True, reason="F-17: e-mail surrogates matched case-sensitively")
def test_c19_email_domain_case_insensitive_restore() -> None:
    """C-19 (ADR-0008: 'e-mail case-insensitive in the domain')."""
    eng = Engine(KEY)
    res = eng.mask([Message("user", "mail jane.tan@acme-corp.test")], "c")
    local, domain = _entry(res, T.EMAIL).surrogate.canonical.split("@")
    assert eng.restore(f"to {local}@{domain.upper()}", res.vault).restored == 1


@pytest.mark.xfail(strict=True, reason="F-17: ADR-0008 ambiguity rule not implemented")
def test_c20_name_components_restored_only_in_name_context() -> None:
    """C-20 (ADR-0008 ambiguity rule): a surrogate given name used generically is not 'restored'."""
    eng = Engine(KEY, Dictionary([("Jane Tan", T.PERSON)]))
    res = eng.mask([Message("user", "I'm Jane Tan.")], "c")
    given = _entry(res, T.PERSON).surrogate.components[0][1]
    out = eng.restore(f"For example, {given} is a common name in many places.", res.vault)
    assert "Jane" not in out.text


@pytest.mark.xfail(strict=True, reason="F-16: phone normalisation is digits-only, not E.164")
def test_c21_phone_normalisation_is_e164() -> None:
    """C-21 (ADR-0002: phone -> E.164 via libphonenumber): one number, one key, with or without +65."""
    assert norm(T.PHONE, "+65 9123 4567") == norm(T.PHONE, "9123 4567")


def test_c22_email_domain_normalised_case_insensitively() -> None:
    """C-22 (ADR-0002 normaliser: lower-case domain, keep local part; mutant M29 survived the review)."""
    assert norm(T.EMAIL, "Jane.Tan@ACME-Corp.TEST") == "Jane.Tan@acme-corp.test"

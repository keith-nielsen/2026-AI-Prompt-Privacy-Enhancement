from prompt_privacy.core.checksums import iban_valid, luhn_valid, nric_valid
from prompt_privacy.core.keys import TokenKey
from prompt_privacy.core.surrogates import Guarantee, Surrogator, transfer_format
from prompt_privacy.core.types import EntityType as T
from prompt_privacy.detectors.base import detect


def test_deterministic_and_scoped(key: TokenKey) -> None:
    s = Surrogator(key)
    assert s.make("a", T.NRIC, "S1234567D") == s.make("a", T.NRIC, "s 1234567 d".replace(" ", ""))
    assert s.make("a", T.NRIC, "S1234567D") != s.make("b", T.NRIC, "S1234567D")
    assert Surrogator(TokenKey.generate()).make("a", T.NRIC, "S1234567D") != s.make("a", T.NRIC, "S1234567D")


def test_g2_constructions_never_valid(key: TokenKey) -> None:
    s = Surrogator(key)
    for i in range(200):
        assert not nric_valid(s.make(str(i), T.NRIC, "S1234567D").canonical)
        assert not luhn_valid(s.make(str(i), T.CARD, "4111111111111111").canonical)
        assert not iban_valid(s.make(str(i), T.IBAN, "GB82WEST12345698765432").canonical)


def test_reserved_ranges(key: TokenKey) -> None:
    s = Surrogator(key)
    us = s.make("x", T.PHONE, "+1 415 555 2671")
    uk = s.make("x", T.PHONE, "07911 123456")
    assert (
        us.guarantee is Guarantee.G1 and us.canonical[5:9] == "5550" and 100 <= int(us.canonical[-3:]) <= 199
    )
    assert uk.canonical.startswith("07700900")
    assert s.make("x", T.EMAIL, "a@b.test").canonical.rsplit("@", 1)[1] in (
        "example.com",
        "example.net",
        "example.org",
    )


def test_sg_phone_has_no_reserved_range_so_token(key: TokenKey) -> None:
    assert Surrogator(key).make("x", T.PHONE, "+65 9123 4567").guarantee is Guarantee.TOKEN


def test_aws_surrogate_still_looks_like_aws(key: TokenKey) -> None:
    sur = Surrogator(key).make("x", T.SECRET, "AKIAIOSFODNN7EXAMPLE").canonical
    assert sur.endswith("EXAMPLE") and len(sur) == 20
    assert [f.subtype for f in detect(sur)] == ["aws_access_key_id"]


def test_format_transfer() -> None:
    assert transfer_format("+65 9123 4567", "+6588887777") == "+65 8888 7777"
    assert transfer_format("s1234567d", "S7654321A") == "s7654321a"
    assert transfer_format("1234", "12345") is None

import pytest

from prompt_privacy.core.checksums import (
    iban_check_digits,
    iban_valid,
    luhn_valid,
    nric_check_letter,
    nric_valid,
)


@pytest.mark.parametrize("value", ["S1234567D", "T9119134I", "s1234567d"])
def test_known_valid_nric(value: str) -> None:
    assert nric_valid(value)


@pytest.mark.parametrize("value", ["S1234567A", "S123456D", "X1234567D", "S12345678"])
def test_invalid_nric(value: str) -> None:
    assert not nric_valid(value)


def test_every_series_round_trips() -> None:
    for prefix in "STFGM":
        assert nric_valid(prefix + "7654321" + nric_check_letter(prefix, "7654321"))


def test_luhn() -> None:
    assert luhn_valid("4111111111111111")
    assert not luhn_valid("4111111111111112")


def test_iban() -> None:
    assert iban_valid("GB82WEST12345698765432")
    assert iban_valid("GB82 WEST 1234 5698 7654 32")
    assert not iban_valid("GB83WEST12345698765432")
    assert iban_check_digits("GB", "WEST12345698765432") == "82"

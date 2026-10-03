"""Check-digit algorithms for structured identifiers (validation and deliberate invalidation)."""

from __future__ import annotations

# Singapore NRIC/FIN: weights 2,7,6,5,4,3,2 over the 7 digits; offset per series; letter tables.
_NRIC_WEIGHTS = (2, 7, 6, 5, 4, 3, 2)
_ST_LETTERS = "JZIHGFEDCBA"  # S, T series
_FG_LETTERS = "XWUTRQPNMLK"  # F, G series
_M_LETTERS = "KLJNPQRTUWX"  # M series (FIN issued from 2022)
_SERIES_OFFSET = {"S": 0, "T": 4, "F": 0, "G": 4, "M": 3}


def nric_check_letter(prefix: str, digits: str) -> str:
    """Return the valid check letter for an NRIC/FIN with the given series prefix and 7 digits."""
    prefix = prefix.upper()
    if prefix not in _SERIES_OFFSET or len(digits) != 7 or not digits.isdigit():
        raise ValueError("NRIC/FIN needs a series letter in STFGM and 7 digits")
    total = sum(int(d) * w for d, w in zip(digits, _NRIC_WEIGHTS, strict=True)) + _SERIES_OFFSET[prefix]
    if prefix in "ST":
        return _ST_LETTERS[total % 11]
    if prefix in "FG":
        return _FG_LETTERS[total % 11]
    return _M_LETTERS[10 - total % 11]


def nric_valid(value: str) -> bool:
    v = value.upper()
    if len(v) != 9 or v[0] not in _SERIES_OFFSET or not v[1:8].isdigit():
        return False
    return nric_check_letter(v[0], v[1:8]) == v[8]


def luhn_check_digit(payload: str) -> int:
    """Check digit that makes payload + digit pass Luhn."""
    total = 0
    for i, ch in enumerate(reversed(payload)):
        d = int(ch)
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return (10 - total % 10) % 10


def luhn_valid(digits: str) -> bool:
    return len(digits) >= 2 and digits.isdigit() and luhn_check_digit(digits[:-1]) == int(digits[-1])


def _iban_numeric(rearranged: str) -> int:
    return int("".join(str(int(c, 36)) for c in rearranged))


def iban_check_digits(country: str, bban: str) -> str:
    """ISO 13616 check digits for country + BBAN."""
    n = _iban_numeric(bban.upper() + country.upper() + "00")
    return f"{98 - n % 97:02d}"


def iban_valid(value: str) -> bool:
    v = value.replace(" ", "").upper()
    if len(v) < 15 or len(v) > 34 or not v[:2].isalpha() or not v[2:4].isdigit() or not v.isalnum():
        return False
    return _iban_numeric(v[4:] + v[:4]) % 97 == 1

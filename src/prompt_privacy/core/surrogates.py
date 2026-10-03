"""Plausible surrogate values (ADR-0008) and typed tokens (ADR-0002).

A surrogate is a *canonical* value (fixed per conversation scope, type and normalised value) that is
*rendered* into the format of each occurrence, so formatting survives the round trip. Construction
ranks: G1 reserved range, G2 invalid check digit, G4 pool-generated, or a typed token where no safe
construction exists (e.g. Singapore phone numbers: no reserved range found).

The per-surrogate RNG is seeded from a keyed HMAC; it chooses *shapes*, it is not used for secrecy.
"""

from __future__ import annotations

import base64
import random
import re
from dataclasses import dataclass
from enum import StrEnum

from prompt_privacy.core.checksums import iban_check_digits, luhn_check_digit, nric_check_letter
from prompt_privacy.core.keys import TokenKey
from prompt_privacy.core.normalise import norm
from prompt_privacy.core.types import EntityType

SURROGATE_VERSION = 1


class Guarantee(StrEnum):
    G1 = "G1"  # reserved range: never real
    G2 = "G2"  # invalid check digit: provably never issued
    G4 = "G4"  # pool-generated: may coincide with a real person
    TOKEN = "token"  # noqa: S105 — typed token, no plausible form


@dataclass(frozen=True, slots=True)
class Surrogate:
    etype: EntityType
    canonical: str  # normalised surrogate value
    guarantee: Guarantee
    components: tuple[tuple[str, str], ...] = ()  # PERSON: (original component, surrogate component)

    def render(self, occurrence: str) -> str:
        """The surrogate in the format of `occurrence` (same separators, case style)."""
        if self.guarantee is Guarantee.TOKEN or self.etype not in _FORMAT_TYPES:
            return self.canonical
        return transfer_format(occurrence, self.canonical) or self.canonical


# Types whose values are character sequences with free formatting (spaces, dashes, brackets).
_FORMAT_TYPES = {EntityType.NRIC, EntityType.CARD, EntityType.IBAN, EntityType.PHONE}


def transfer_format(template: str, chars: str) -> str | None:
    """Write `chars` (alphanumerics, '+' allowed first) into the alphanumeric slots of `template`.

    Returns None when the slot count differs (then the caller falls back to the canonical form).
    """
    body = chars.lstrip("+")
    slots = [i for i, c in enumerate(template) if c.isalnum()]
    if len(slots) != len(body):
        return None
    out = list(template)
    for i, c in zip(slots, body, strict=True):
        out[i] = c.lower() if template[i].islower() else c
    if chars.startswith("+") and not template.lstrip().startswith("+"):
        return None
    return "".join(out)


_GIVEN = (
    "Wei Ming",
    "Siti",
    "Arjun",
    "Mei Ling",
    "Hafiz",
    "Priya",
    "Daniel",
    "Aisha",
    "Kenji",
    "Elena",
    "Marcus",
    "Nurul",
    "Ravi",
    "Sofia",
    "Tomas",
    "Yan Ting",
    "Farid",
    "Leila",
    "Owen",
    "Ingrid",
)
_FAMILY = (
    "Koh",
    "Rahman",
    "Pillai",
    "Teo",
    "Ismail",
    "Nair",
    "Lindqvist",
    "Oyelaran",
    "Tanaka",
    "Moreau",
    "Quek",
    "Hashim",
    "Sundaram",
    "Varga",
    "Ferreira",
    "Goh",
    "Okafor",
    "Brennan",
    "Halvorsen",
    "Ong",
)
_EMAIL_DOMAINS = ("example.com", "example.net", "example.org")
_TEST_NETS = ("192.0.2", "198.51.100", "203.0.113")  # RFC 5737


class Surrogator:
    """Deterministic surrogate factory for one token-key epoch."""

    def __init__(self, key: TokenKey) -> None:
        self._key = key

    def _rng(self, scope: str, etype: EntityType, value_norm: str, attempt: int) -> random.Random:
        seed = self._key.mac("ppe/sur/v1", scope, etype.value, value_norm, str(attempt))
        return random.Random(int.from_bytes(seed, "big"))  # noqa: S311 — shape selection, not secrecy

    def token(self, scope: str, etype: EntityType, value_norm: str, attempt: int = 0) -> Surrogate:
        d = self._key.mac("ppe/tok/v1", scope, etype.value, value_norm, str(attempt))
        suffix = base64.b32encode(d).decode().lower()[: 10 if attempt == 0 else 16]
        return Surrogate(etype, f"<{etype.value}_{suffix}>", Guarantee.TOKEN)

    def make(self, scope: str, etype: EntityType, value: str, attempt: int = 0) -> Surrogate:
        v = norm(etype, value)
        r = self._rng(scope, etype, v, attempt)
        match etype:
            case EntityType.NRIC:
                return Surrogate(etype, _nric(r, v), Guarantee.G2)
            case EntityType.CARD:
                return Surrogate(etype, _card(r, v), Guarantee.G2)
            case EntityType.IBAN:
                return Surrogate(etype, _iban(r, v), Guarantee.G2)
            case EntityType.EMAIL:
                g, f = r.choice(_GIVEN), r.choice(_FAMILY)
                local = f"{g}.{f}".lower().replace(" ", "")
                return Surrogate(etype, f"{local}@{r.choice(_EMAIL_DOMAINS)}", Guarantee.G1)
            case EntityType.PHONE:
                phone = _phone(r, v)
                return (
                    Surrogate(etype, phone, Guarantee.G1) if phone else self.token(scope, etype, v, attempt)
                )
            case EntityType.IPV4:
                return Surrogate(etype, f"{r.choice(_TEST_NETS)}.{r.randint(1, 254)}", Guarantee.G1)
            case EntityType.IPV6:
                return Surrogate(
                    etype, f"2001:db8:{r.randint(1, 0xFFFF):x}::{r.randint(1, 0xFFFF):x}", Guarantee.G1
                )
            case EntityType.SECRET:
                return Surrogate(etype, _secret(r, value), Guarantee.G2)
            case EntityType.PERSON:
                return self._person(scope, value, attempt)
        return self.token(scope, etype, v, attempt)

    def _person(self, scope: str, value: str, attempt: int) -> Surrogate:
        parts = value.split()
        comps: list[tuple[str, str]] = []
        for i, part in enumerate(parts):
            r = self._rng(scope, EntityType.PERSON, "component:" + part.casefold(), attempt)
            pool = _FAMILY if (i == len(parts) - 1 and len(parts) > 1) else _GIVEN
            comps.append((part, r.choice(pool).split()[0]))
        return Surrogate(EntityType.PERSON, " ".join(s for _, s in comps), Guarantee.G4, tuple(comps))


def _digits(r: random.Random, n: int) -> str:
    return "".join(str(r.randint(0, 9)) for _ in range(n))


def _nric(r: random.Random, v: str) -> str:
    prefix, digits = v[0], _digits(r, 7)
    valid = nric_check_letter(prefix, digits)
    letters = [c for c in "ABCDEFGHIJKLMNPQRTUWXZ" if c != valid]
    return prefix + digits + r.choice(letters)  # deliberately invalid check letter (G2)


def _card(r: random.Random, v: str) -> str:
    body = v[0] + _digits(r, len(v) - 2)
    valid = luhn_check_digit(body)
    return body + str((valid + r.randint(1, 9)) % 10)  # deliberately fails Luhn (G2)


def _iban(r: random.Random, v: str) -> str:
    country, bban = (
        v[:2],
        "".join(str(r.randint(0, 9)) if c.isdigit() else chr(r.randint(65, 90)) for c in v[4:]),
    )
    valid = int(iban_check_digits(country, bban))
    bad = (valid + r.randint(1, 96)) % 100
    if bad < 2:  # check digits 00/01 are never valid either; keep them two-digit and wrong
        bad += 2
    return f"{country}{bad:02d}{bban}"  # deliberately wrong mod-97 check (G2)


def _phone(r: random.Random, v: str) -> str | None:
    """NANP 555-0100..0199 and UK Ofcom drama ranges (G1); None where no reserved range is known."""
    digits = v.lstrip("+")
    if v.startswith("+1") or (len(digits) == 10 and digits[0] in "2345678" and not v.startswith("+")):
        area = f"{r.randint(2, 9)}{_digits(r, 2)}"
        local = f"{area}5550{r.randint(100, 199)}"
        return ("+1" + local) if v.startswith("+") else local
    if v.startswith("+447") or (digits.startswith("07") and len(digits) == 11):
        rest = f"7700900{r.randint(0, 999):03d}"
        return ("+44" + rest) if v.startswith("+") else ("0" + rest)
    return None


_SECRET_PREFIX = re.compile(
    r"^(?:AKIA|ASIA|gh[pousr]_|github_pat_|sk-ant-|sk-proj-|sk-|xox[abposr]-|AIza|[sr]k_(?:live|test)_)"
)


def _secret(r: random.Random, value: str) -> str:
    if value.startswith("-----BEGIN"):
        tag = "".join(r.choice("0123456789abcdef") for _ in range(16))
        return f"-----BEGIN PRIVATE KEY-----\nEXAMPLE{tag}\n-----END PRIVATE KEY-----"
    m = _SECRET_PREFIX.match(value)
    prefix = m.group() if m else ""
    body_len = len(value) - len(prefix)
    if prefix in ("AKIA", "ASIA") and body_len == 16:
        return prefix + "".join(r.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(9)) + "EXAMPLE"
    out = []
    for c in value[len(prefix) :]:
        if c.isdigit():
            out.append(str(r.randint(0, 9)))
        elif c.isupper():
            out.append(chr(r.randint(65, 90)))
        elif c.islower():
            out.append(chr(r.randint(97, 122)))
        else:
            out.append(c)
    body = "".join(out)
    if body_len > 12:  # mark as fake where length allows (AWS documentation convention)
        body = body[:-7] + "EXAMPLE"
    return prefix + body

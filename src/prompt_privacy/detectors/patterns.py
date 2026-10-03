"""Stage 1 checksummed / structured identifier patterns (ADR-0005).

`strict=True` (detection) requires a valid check digit where the type has one. `strict=False`
(restore, ADR-0008) accepts the shape alone, because G2 surrogates carry a deliberately invalid
check digit and must still be found when a model echoes or reformats them.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterator

from prompt_privacy.core.checksums import iban_valid, luhn_valid, nric_valid
from prompt_privacy.core.types import EntityType

_NRIC = re.compile(r"(?<![A-Za-z0-9])[STFGMstfgm][ -]?\d{7}[ -]?[A-Za-z](?![A-Za-z0-9])")
# Cards: compact 13-19 digits, groups of 4 (one consistent separator), or Amex 4-6-5. No adjacent \w.
_CARD = re.compile(
    r"(?<![\w-])(?:\d{13,19}|\d{4}([ -])\d{4}\1\d{4}\1\d{1,7}|\d{4}([ -])\d{6}\2\d{5})(?![\w-])"
)
_IBAN = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]{2}\d{2}(?:[ ]?[A-Za-z0-9]){11,30}(?![A-Za-z0-9])")
_EMAIL = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?![\w-])")
# International (+CC ...) or common national formats; validated by digit count below.
_PHONE = re.compile(
    r"(?<![\w+])(?:\+\d{1,3}[ .-]?)?(?:\(\d{1,4}\)[ .-]?)?\d{2,4}(?:[ .-]?\d{2,4}){1,4}(?![\w])"
)
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6 = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])")


def _digits(s: str) -> str:
    return "".join(c for c in s if c.isdigit())


def find_structured(
    shadow: str, strict: bool = True, phone_context: bool = False
) -> Iterator[tuple[int, int, EntityType]]:
    """Yield (start, end, type) spans in the shadow text."""
    for m in _EMAIL.finditer(shadow):
        yield m.start(), m.end(), EntityType.EMAIL
    for m in _NRIC.finditer(shadow):
        if not strict or nric_valid(re.sub(r"[ -]", "", m.group())):
            yield m.start(), m.end(), EntityType.NRIC
    for m in _IBAN.finditer(shadow):
        compact = m.group().replace(" ", "")
        if compact[:2].isalpha() and (iban_valid(compact) if strict else len(compact) >= 15):
            yield m.start(), m.end(), EntityType.IBAN
    for m in _CARD.finditer(shadow):
        d = _digits(m.group())
        if 13 <= len(d) <= 19 and (luhn_valid(d) if strict else True):
            yield m.start(), m.end(), EntityType.CARD
    for m in _IPV4.finditer(shadow):
        try:
            ipaddress.IPv4Address(m.group())
        except ValueError:
            continue
        yield m.start(), m.end(), EntityType.IPV4
    for m in _IPV6.finditer(shadow):
        try:
            ipaddress.IPv6Address(m.group())
        except ValueError:
            continue
        yield m.start(), m.end(), EntityType.IPV6
    blocked = [(m.start(), m.end()) for m in _DATETIME.finditer(shadow)]
    for m in _PHONE.finditer(shadow):
        if any(m.start() < e and b < m.end() for b, e in blocked):
            continue
        context = shadow[max(0, m.start() - _CONTEXT_WINDOW) : m.start()]
        if plausible_phone(m.group(), context, phone_context):
            yield m.start(), m.end(), EntityType.PHONE


_DATETIME = re.compile(
    r"\b\d{4}[-/.]\d{1,2}[-/.]\d{1,2}(?:[ T]\d{1,2}:\d{2}(?::\d{2})?)?\b"
    r"|\b\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4}\b|\b\d{1,2}:\d{2}(?::\d{2})?\b"
    r"|\bISBN[- ]?(?:1[03])?:?[ ]?[\d -]{10,17}"
)
_CONTEXT_WINDOW = 40
_PHONE_CONTEXT = re.compile(
    r"(?i)\b(?:phone|tel|telephone|mobile|mob|cell|hp|h/p|call|calling|contact|reach|whatsapp|sms|text|fax|ring|dial)\b"
)


def plausible_phone(text: str, context: str = "", require_context: bool = True) -> bool:
    """International numbers by length. National numbers need an SG, NANP or UK shape *and* a context
    word before them (an 8-digit order number and an SG mobile number look identical)."""
    d = _digits(text)
    if text.startswith("+"):
        return 8 <= len(d) <= 15
    shaped = (
        (len(d) == 8 and d[0] in "3689")  # Singapore
        or (len(d) == 10 and d[0] in "23456789")  # NANP: area code cannot start with 0/1
        or (len(d) in (10, 11) and d[0] == "0")  # UK and other trunk-prefixed national formats
    )
    return shaped and (not require_context or _PHONE_CONTEXT.search(context) is not None)

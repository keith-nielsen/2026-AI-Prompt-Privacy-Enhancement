"""Per-type value normalisation, versioned (ADR-0002): the same value always yields the same key."""

from __future__ import annotations

import re
import unicodedata

from prompt_privacy.core.types import EntityType

NORM_VERSION = 1

_NON_ALNUM = re.compile(r"[^0-9A-Za-z]")
_NON_DIGIT = re.compile(r"\D")


def norm(etype: EntityType, value: str) -> str:
    v = unicodedata.normalize("NFKC", value).strip()
    match etype:
        case EntityType.NRIC | EntityType.IBAN:
            return _NON_ALNUM.sub("", v).upper()
        case EntityType.CARD:
            return _NON_DIGIT.sub("", v)
        case EntityType.PHONE:
            digits = _NON_DIGIT.sub("", v)
            return ("+" + digits) if v.startswith("+") else digits
        case EntityType.EMAIL:
            local, _, domain = v.rpartition("@")
            return f"{local}@{domain.lower()}"  # local part may be case-sensitive
        case EntityType.IPV4 | EntityType.SECRET:
            return v
        case EntityType.IPV6:
            return v.lower()
        case EntityType.PERSON | EntityType.TERM:
            return " ".join(v.casefold().split())
    raise ValueError(f"no normaliser for {etype}")

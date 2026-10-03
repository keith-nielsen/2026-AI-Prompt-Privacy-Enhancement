"""Shared types: entity types, data classes, findings."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class EntityType(StrEnum):
    NRIC = "NRIC"  # Singapore NRIC/FIN
    CARD = "CARD"
    IBAN = "IBAN"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    IPV4 = "IPV4"
    IPV6 = "IPV6"
    SECRET = "SECRET"  # noqa: S105 — entity type name
    PERSON = "PERSON"  # from span models or operator dictionaries
    TERM = "TERM"  # operator dictionary term (client, project code name)


class DataClass(StrEnum):
    SECRET = "secret"  # noqa: S105 — data class name
    DIRECT_IDENTIFIER = "direct_identifier"
    SPECIAL = "special"
    ATTRIBUTE = "attribute"


DEFAULT_CLASS: dict[EntityType, DataClass] = {
    EntityType.SECRET: DataClass.SECRET,
    **{t: DataClass.DIRECT_IDENTIFIER for t in EntityType if t is not EntityType.SECRET},
}


@dataclass(frozen=True, slots=True)
class Finding:
    """A detected span in the *original* text (offsets are into the original, not the shadow)."""

    start: int
    end: int
    type: EntityType
    value: str
    detector: str
    score: float = 1.0
    subtype: str = ""  # e.g. secret rule id, phone region

    @property
    def data_class(self) -> DataClass:
        return DEFAULT_CLASS[self.type]

    def overlaps(self, other: Finding) -> bool:
        return self.start < other.end and other.start < self.end

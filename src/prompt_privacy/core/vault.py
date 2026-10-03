"""Request-scoped vault: real value ↔ surrogate for one request (ADR-0002). Never persisted."""

from __future__ import annotations

from dataclasses import dataclass, field

from prompt_privacy.core.normalise import norm
from prompt_privacy.core.surrogates import Surrogate, Surrogator
from prompt_privacy.core.types import EntityType

MAX_PROBES = 32


@dataclass
class Entry:
    etype: EntityType
    value_norm: str
    surrogate: Surrogate
    surfaces: list[str] = field(default_factory=list)  # original surface forms, first seen first


class Vault:
    """Issues deterministic surrogates; detects and avoids collisions by deterministic probing."""

    def __init__(
        self, surrogator: Surrogator, scope: str, conversation_text: str = "", form: str = "surrogate"
    ) -> None:
        self._s = surrogator
        self.scope = scope
        self._text = conversation_text
        self._form = form  # "surrogate" | "token"
        self.entries: dict[tuple[EntityType, str], Entry] = {}
        self._by_canonical: dict[tuple[EntityType, str], Entry] = {}
        self._originals: set[tuple[EntityType, str]] = set()

    def note_original(self, etype: EntityType, value: str) -> None:
        """Register a real value before issuing, so no surrogate can equal any real value."""
        self._originals.add((etype, norm(etype, value)))

    def issue(self, etype: EntityType, value: str) -> Entry:
        key = (etype, norm(etype, value))
        entry = self.entries.get(key)
        if entry is None:
            entry = Entry(etype, key[1], self._new_surrogate(etype, value))
            self.entries[key] = entry
            self._by_canonical[(etype, norm(etype, entry.surrogate.canonical))] = entry
        if value not in entry.surfaces:
            entry.surfaces.append(value)
        return entry

    def _new_surrogate(self, etype: EntityType, value: str) -> Surrogate:
        for attempt in range(MAX_PROBES):
            s = (
                self._s.token(self.scope, etype, norm(etype, value), attempt)
                if self._form == "token"
                else self._s.make(self.scope, etype, value, attempt)
            )
            ckey = (etype, norm(etype, s.canonical))
            if ckey in self._by_canonical or ckey in self._originals or s.canonical in self._text:
                continue
            return s
        raise RuntimeError(f"no collision-free surrogate for {etype} after {MAX_PROBES} probes")

    def by_surrogate_norm(self, etype: EntityType, value: str) -> Entry | None:
        return self._by_canonical.get((etype, norm(etype, value)))

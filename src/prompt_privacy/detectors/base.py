"""Run Stage 0 + Stage 1 detectors and resolve overlaps."""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence

from prompt_privacy.core.shadow import build_shadow
from prompt_privacy.core.types import EntityType, Finding
from prompt_privacy.detectors.patterns import find_structured
from prompt_privacy.detectors.secrets import SECRET_RULES

# When spans overlap: secrets win, then checksummed types, then the rest; then the longer span.
_PRIORITY: dict[EntityType, int] = {
    EntityType.SECRET: 0,
    EntityType.NRIC: 1,
    EntityType.IBAN: 1,
    EntityType.CARD: 1,
    EntityType.EMAIL: 2,
    EntityType.TERM: 3,
    EntityType.PERSON: 3,
    EntityType.IPV6: 4,
    EntityType.IPV4: 4,
    EntityType.PHONE: 5,
}


class Dictionary:
    """Operator dictionary: exact terms (client names, code names, staff names), matched on the shadow."""

    def __init__(self, terms: Iterable[tuple[str, EntityType]]) -> None:
        items = sorted({(t.strip(), et) for t, et in terms if t.strip()}, key=lambda x: -len(x[0]))
        self._types = {t.casefold(): et for t, et in items}
        self._re = (
            re.compile(r"(?<!\w)(?:" + "|".join(re.escape(t) for t, _ in items) + r")(?!\w)", re.IGNORECASE)
            if items
            else None
        )

    def find(self, shadow: str) -> Iterable[tuple[int, int, EntityType]]:
        if self._re is None:
            return
        for m in self._re.finditer(shadow):
            yield m.start(), m.end(), self._types[m.group().casefold()]


def detect(
    text: str, dictionary: Dictionary | None = None, strict: bool = True, phone_context: bool = False
) -> list[Finding]:
    """All Stage 1 findings in `text`, overlaps resolved, sorted by position."""
    shadow = build_shadow(text)
    raw: list[Finding] = []

    def add(s: int, e: int, et: EntityType, detector: str, subtype: str = "") -> None:
        os_, oe = shadow.to_original(s, e)
        raw.append(Finding(os_, oe, et, text[os_:oe], detector, 1.0, subtype))

    for rule_id, rx in SECRET_RULES:
        for m in rx.finditer(shadow.text):
            s, e = m.span("s") if "s" in rx.groupindex else m.span()
            add(s, e, EntityType.SECRET, "rules.secrets", rule_id)
    for s, e, et in find_structured(shadow.text, strict=strict, phone_context=phone_context):
        add(s, e, et, "rules.patterns")
    if dictionary is not None:
        for s, e, et in dictionary.find(shadow.text):
            add(s, e, et, "rules.dictionary")
    return resolve_overlaps(raw)


def resolve_overlaps(findings: Sequence[Finding]) -> list[Finding]:
    ranked = sorted(findings, key=lambda f: (_PRIORITY[f.type], -(f.end - f.start), f.start))
    kept: list[Finding] = []
    for f in ranked:
        if not any(f.overlaps(k) for k in kept):
            kept.append(f)
    return sorted(kept, key=lambda f: f.start)

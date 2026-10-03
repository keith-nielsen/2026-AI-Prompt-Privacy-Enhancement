"""Stage 0: a detection 'shadow' of the text with an offset map back to the original (ADR-0005).

The shadow folds characters attackers use to dodge pattern detectors (full-width digits, zero-width
and bidi controls, compatibility forms) while keeping every shadow character traceable to a span
of the original, so masking is always applied to the original text.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass

# Characters removed from the shadow: zero-width, joiners, BOM, soft hyphen, bidi controls.
_INVISIBLE = frozenset(
    chr(c)
    for c in (
        0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD,  # zero-width, joiners, BOM, soft hyphen
        0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069,  # bidi controls
    )
)  # fmt: skip


@dataclass(frozen=True, slots=True)
class Shadow:
    text: str
    # starts[i] / ends[i]: span in the original text that produced shadow character i
    starts: tuple[int, ...]
    ends: tuple[int, ...]

    def to_original(self, start: int, end: int) -> tuple[int, int]:
        """Map a shadow span [start, end) to the original text."""
        if start >= end:
            raise ValueError("empty span")
        return self.starts[start], self.ends[end - 1]


def build_shadow(original: str) -> Shadow:
    out: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    for i, ch in enumerate(original):
        if ch in _INVISIBLE:
            continue
        folded = unicodedata.normalize("NFKC", ch)
        for f in folded:
            out.append(f)
            starts.append(i)
            ends.append(i + 1)
    return Shadow("".join(out), tuple(starts), tuple(ends))

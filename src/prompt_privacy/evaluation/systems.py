"""Systems under test. Each returns spans labelled with canonical types (the `EntityType` values).

Further systems (e.g. a Presidio baseline) map their own entity names onto the same types here, so
every system is scored by the same `Scorer` with the same dataset label map.
"""

from __future__ import annotations

from prompt_privacy.detectors.base import detect
from prompt_privacy.evaluation.scoring import Span, System


def ppe_rules(phone_context: bool = False) -> System:
    """PPE Stage 0 + Stage 1 (deterministic rules), exactly as `ppe scan` runs them."""

    def run(text: str) -> list[Span]:
        return [Span(f.start, f.end, f.type.value) for f in detect(text, phone_context=phone_context)]

    return run

"""Stage 1 cost must grow linearly with input size (bench 2026-10-03: 10 → 100 KB cost 21×).

Timing bound is loose (per-KB cost at 400 KB within 2.5× of 10 KB) so a busy host does not flake it;
the quadratic version measured ~6.5×. The overlap resolver is also checked against the naive one.
"""

from __future__ import annotations

import time

from hypothesis import given
from hypothesis import strategies as st

from prompt_privacy.core.types import EntityType, Finding
from prompt_privacy.corpus.generator import Generator
from prompt_privacy.detectors.base import detect, resolve_overlaps

_ITEMS = [it.text for it in Generator(20261002).items(400)]


def _doc(nbytes: int) -> str:
    out: list[str] = []
    n = 0
    while n < nbytes:
        out.append(_ITEMS[len(out) % len(_ITEMS)])
        n += len(out[-1]) + 2
    return "\n\n".join(out)[:nbytes]


def _ms_per_kb(kb: int) -> float:
    text = _doc(kb * 1024)
    best = float("inf")
    for _ in range(3):
        t0 = time.perf_counter()
        detect(text)
        best = min(best, time.perf_counter() - t0)
    return best * 1000 / kb


def test_detect_cost_is_linear_in_size() -> None:
    detect(_doc(1024))  # warm-up
    small, large = _ms_per_kb(10), _ms_per_kb(400)
    assert large < 2.5 * small, f"10 KB: {small:.3f} ms/KB, 400 KB: {large:.3f} ms/KB"


def _naive(findings: list[Finding]) -> list[Finding]:
    from prompt_privacy.detectors.base import _PRIORITY

    ranked = sorted(findings, key=lambda f: (_PRIORITY[f.type], -(f.end - f.start), f.start))
    kept: list[Finding] = []
    for f in ranked:
        if not any(f.overlaps(k) for k in kept):
            kept.append(f)
    return sorted(kept, key=lambda f: f.start)


_finding = st.builds(
    lambda s, n, t: Finding(s, s + n, t, "x" * n, "test"),
    st.integers(0, 200),
    st.integers(1, 30),
    st.sampled_from(list(EntityType)),
)


@given(st.lists(_finding, max_size=60))
def test_resolve_overlaps_matches_naive(findings: list[Finding]) -> None:
    assert resolve_overlaps(findings) == _naive(findings)

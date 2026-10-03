"""Detection benchmark on the synthetic corpus (PDPC §8.3 metric; NIST AI 600-1 MEASURE 2.10 evidence).

A gold span counts as found when a finding of the same type overlaps it. A finding that overlaps no
gold span of its type is a false positive. Spans that need a span model (`detector: ner`) and
known-gap variants are reported in their own rows instead of being hidden in the totals.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field

from prompt_privacy.corpus.generator import Generator
from prompt_privacy.detectors.base import detect


@dataclass
class TypeStats:
    support: int = 0
    tp: int = 0
    fn: int = 0
    fp: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 1.0

    @property
    def recall(self) -> float:
        return self.tp / self.support if self.support else 1.0


@dataclass
class BenchReport:
    items: int
    seed: int
    phone_context: bool = False
    by_type: dict[str, TypeStats] = field(default_factory=dict)
    by_variant: dict[str, Counter[str]] = field(default_factory=dict)  # variant -> {found, total}
    out_of_scope: Counter[str] = field(default_factory=Counter)  # needs Stage 2 (ner) / known gaps

    def table(self) -> str:
        lines = [
            f"Stage 1 (rules) on synthetic corpus: {self.items} items, seed {self.seed}, "
            f"phone_context={'required' if self.phone_context else 'optional'}",
            "",
            f"{'type':<8} {'support':>8} {'recall':>8} {'precision':>10} {'FP':>5}",
        ]
        for t, s in sorted(self.by_type.items()):
            lines.append(f"{t:<8} {s.support:>8} {s.recall:>8.3f} {s.precision:>10.3f} {s.fp:>5}")
        lines += ["", f"{'variant':<16} {'recall':>8} {'n':>6}"]
        for v, c in sorted(self.by_variant.items()):
            lines.append(f"{v:<16} {c['found'] / c['total']:>8.3f} {c['total']:>6}")
        lines += ["", "not counted above (reported, not hidden):"]
        lines += [f"  {k}: {n}" for k, n in sorted(self.out_of_scope.items())]
        return "\n".join(lines)


def run(n: int = 2000, seed: int = 20261002, phone_context: bool = False) -> BenchReport:
    rep = BenchReport(n, seed, phone_context)
    stats: dict[str, TypeStats] = defaultdict(TypeStats)
    variants: dict[str, Counter[str]] = defaultdict(Counter)
    for item in Generator(seed).items(n):
        findings = detect(item.text, phone_context=phone_context)
        gold = [s for s in item.spans if s.detector == "rules" and not s.expected_gap]
        for s in item.spans:
            if s.detector != "rules":
                rep.out_of_scope[f"{s.type} needs span model (Stage 2)"] += 1
            elif s.expected_gap:
                found = any(f.type.value == s.type and f.start < s.end and s.start < f.end for f in findings)
                rep.out_of_scope[f"{s.type}/{s.variant} known gap ({'found' if found else 'missed'})"] += 1
        for s in gold:
            st = stats[s.type]
            st.support += 1
            hit = any(f.type.value == s.type and f.start < s.end and s.start < f.end for f in findings)
            st.tp += hit
            st.fn += not hit
            variants[s.variant]["total"] += 1
            variants[s.variant]["found"] += hit
        for f in findings:
            if not any(s.type == f.type.value and f.start < s.end and s.start < f.end for s in item.spans):
                stats[f.type.value].fp += 1
    rep.by_type, rep.by_variant = dict(stats), dict(variants)
    return rep

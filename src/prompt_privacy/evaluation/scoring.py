"""Span-level scoring of a system against gold spans from an external dataset.

Gold spans carry the dataset's own labels. A label map sends a label to a canonical type (the
`EntityType` values) when every span with that label is of that type; system spans carry canonical
types. Every view below is reported, none is folded into another:

- typed recall, overlap: a mapped gold span of type T is found when a system span of type T overlaps it.
- typed recall, strict: ... when a system span of type T has exactly the same offsets.
- any-type coverage, per dataset label (mapped or not): the gold span is overlapped by a system span of
  any type. This is the protection view: a value swapped under the wrong type still did not leave.
- precision, per system span: typed when it overlaps a gold span whose label maps to its type, or whose
  label is listed as compatible with it (labels that hold the type among others, e.g. IBANs inside
  `account_number`); any-label when it overlaps any gold span. The rest count as false positives,
  with the caveat that a dataset can leave real identifiers unlabelled.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Span:
    start: int
    end: int
    label: str

    def overlaps(self, other: Span) -> bool:
        return self.start < other.end and other.start < self.end


@dataclass(frozen=True)
class Doc:
    uid: str
    text: str
    gold: tuple[Span, ...]
    tags: tuple[tuple[str, str], ...] = ()  # e.g. (("locale", "us"),): slice keys, never content


System = Callable[[str], list[Span]]


@dataclass
class TypeCounts:
    support: int = 0  # mapped gold spans of this type
    found_overlap: int = 0
    found_strict: int = 0
    predicted: int = 0  # system spans of this type
    pred_typed: int = 0  # ... overlapping a gold span of this type (or a compatible label)
    pred_any: int = 0  # ... overlapping any gold span

    def as_dict(self) -> dict[str, Any]:
        def ratio(a: int, b: int) -> float | None:
            return round(a / b, 4) if b else None

        r, p = ratio(self.found_overlap, self.support), ratio(self.pred_typed, self.predicted)
        return {
            "support": self.support,
            "found_overlap": self.found_overlap,
            "found_strict": self.found_strict,
            "recall_overlap": r,
            "recall_strict": ratio(self.found_strict, self.support),
            "predicted": self.predicted,
            "precision_typed": p,
            "precision_any_label": ratio(self.pred_any, self.predicted),
            "f1_overlap": round(2 * r * p / (r + p), 4)
            if r is not None and p is not None and r + p
            else None,
        }


@dataclass
class Scorer:
    label_map: Mapping[str, str]
    compatible: Mapping[str, frozenset[str]] = field(default_factory=dict)  # type -> extra gold labels
    docs: int = 0
    by_type: dict[str, TypeCounts] = field(default_factory=lambda: defaultdict(TypeCounts))
    by_label: dict[str, Counter[str]] = field(default_factory=lambda: defaultdict(Counter))
    confusion: dict[str, Counter[str]] = field(default_factory=lambda: defaultdict(Counter))
    by_slice: dict[str, dict[str, TypeCounts]] = field(
        default_factory=lambda: defaultdict(lambda: defaultdict(TypeCounts))
    )

    def _typed_match(self, pred: Span, gold: Span) -> bool:
        return self.label_map.get(gold.label) == pred.label or gold.label in self.compatible.get(
            pred.label, frozenset()
        )

    def add(self, doc: Doc, predicted: Iterable[Span]) -> None:
        preds = list(predicted)
        self.docs += 1
        slices = [self.by_slice[f"{k}={v}"] for k, v in doc.tags]
        for g in doc.gold:
            covered = any(p.overlaps(g) for p in preds)
            lab = self.by_label[g.label]
            lab["support"] += 1
            lab["covered_any_type"] += covered
            t = self.label_map.get(g.label)
            if t is None:
                continue
            hit = any(p.label == t and p.overlaps(g) for p in preds)
            exact = any(p.label == t and p.start == g.start and p.end == g.end for p in preds)
            lab["found_typed"] += hit
            for counts in (self.by_type[t], *(s[t] for s in slices)):
                counts.support += 1
                counts.found_overlap += hit
                counts.found_strict += exact
        for p in preds:
            over = [g for g in doc.gold if p.overlaps(g)]
            typed = any(self._typed_match(p, g) for g in over)
            for counts in (self.by_type[p.label], *(s[p.label] for s in slices)):
                counts.predicted += 1
                counts.pred_typed += typed
                counts.pred_any += bool(over)
            labels = {g.label for g in over} or {"(no gold span)"}
            for label in labels:
                self.confusion[p.label][label] += 1

    def report(self) -> dict[str, Any]:
        mapped = [t for t in self.by_type if any(v == t for v in self.label_map.values())]
        micro = TypeCounts()
        for t in mapped:
            c = self.by_type[t]
            micro.support += c.support
            micro.found_overlap += c.found_overlap
            micro.found_strict += c.found_strict
            micro.predicted += c.predicted
            micro.pred_typed += c.pred_typed
            micro.pred_any += c.pred_any
        gold_total = sum(c["support"] for c in self.by_label.values())
        covered_total = sum(c["covered_any_type"] for c in self.by_label.values())
        return {
            "docs": self.docs,
            "label_map": dict(sorted(self.label_map.items())),
            "compatible": {k: sorted(v) for k, v in sorted(self.compatible.items())},
            "by_type": {t: self.by_type[t].as_dict() for t in sorted(self.by_type)},
            "micro_mapped_types": micro.as_dict(),
            "any_type_coverage_all_labels": {
                "gold_spans": gold_total,
                "covered": covered_total,
                "rate": round(covered_total / gold_total, 4) if gold_total else None,
            },
            "by_label": {
                label: {
                    "support": c["support"],
                    "maps_to": self.label_map.get(label),
                    "covered_any_type": c["covered_any_type"],
                    "coverage_any_type": round(c["covered_any_type"] / c["support"], 4),
                }
                for label, c in sorted(self.by_label.items())
            },
            "confusion": {t: dict(sorted(c.items())) for t, c in sorted(self.confusion.items())},
            "by_slice": {
                s: {t: v.as_dict() for t, v in sorted(types.items())}
                for s, types in sorted(self.by_slice.items())
            },
        }


def table(report: Mapping[str, Any]) -> str:
    """Human-readable summary of `Scorer.report()` (labels and numbers only)."""

    def f(x: float | None) -> str:
        return "   n/a" if x is None else f"{x:6.3f}"

    lines = [
        f"{'type':<8} {'support':>8} {'R_overlap':>9} {'R_strict':>9} {'pred':>7} {'P_typed':>8} "
        f"{'P_any':>7} {'F1':>7}"
    ]
    rows = [*report["by_type"].items(), ("micro*", report["micro_mapped_types"])]
    for t, c in rows:
        lines.append(
            f"{t:<8} {c['support']:>8} {f(c['recall_overlap']):>9} {f(c['recall_strict']):>9} "
            f"{c['predicted']:>7} {f(c['precision_typed']):>8} {f(c['precision_any_label']):>7} "
            f"{f(c['f1_overlap']):>7}"
        )
    cov = report["any_type_coverage_all_labels"]
    lines += [
        "  * micro over types that dataset labels map to",
        "",
        f"any-type coverage, all {len(report['by_label'])} dataset labels: "
        f"{cov['covered']}/{cov['gold_spans']} = {f(cov['rate']).strip()}",
        "",
        f"{'dataset label':<32} {'support':>8} {'maps_to':>8} {'covered':>8}",
    ]
    for label, c in sorted(report["by_label"].items(), key=lambda kv: -kv[1]["coverage_any_type"]):
        lines.append(f"{label:<32} {c['support']:>8} {c['maps_to'] or '-':>8} {f(c['coverage_any_type']):>8}")
    lines += ["", "system spans by overlapped gold label (top 6 per type):"]
    for t, c in report["confusion"].items():
        top = sorted(c.items(), key=lambda kv: -kv[1])[:6]
        lines.append(f"  {t:<7} " + ", ".join(f"{k} {v}" for k, v in top))
    return "\n".join(lines)

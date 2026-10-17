"""Span-level scoring of a system against gold spans from an external dataset.

Gold spans carry the dataset's own labels. A label map sends a label to a canonical type (the
`EntityType` values) when every span with that label is of that type; system spans carry canonical
types. Every view below is reported, none is folded into another:

- typed recall, overlap: a mapped gold span of type T is found when a system span of type T overlaps it.
- typed recall, strict: ... when a system span of type T has exactly the same offsets.
- any-type coverage, per dataset label (mapped or not): the gold span is overlapped by a system span of
  any type. This is the protection view: a value swapped under the wrong type still did not leave.
- micro averages: over every mapped type (same denominator for every system, so directly comparable)
  and over the types the system claims to detect (its own scope).
- precision, per system span: typed when it overlaps a gold span whose label maps to its type, or whose
  label is listed as compatible with it (labels that hold the type among others, e.g. IBANs inside
  `account_number`); any-label when it overlaps any gold span. The rest count as false positives,
  with the caveat that a dataset can leave real identifiers unlabelled.

A dataset with open-ended labels (CredData: verdict plus rule name, e.g. `T:Password`) maps and marks
compatible by label prefix as well; an exact label entry wins over a prefix.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from prompt_privacy.core.types import EntityType

# Canonical types: PPE's entity types plus types that other systems detect and datasets label. A
# dataset's label map and every system's output use only these (unmapped system types pass through
# under their own names and count for coverage and confusion only).
EXTRA_TYPES = frozenset({"LOCATION", "DATE_TIME", "URL", "US_SSN", "ORGANIZATION", "AGE", "MAC_ADDRESS"})
CANONICAL_TYPES = frozenset(t.value for t in EntityType) | EXTRA_TYPES


@dataclass(frozen=True)
class Span:
    start: int
    end: int
    label: str
    score: float = 1.0  # system confidence; gold spans and rules use 1.0

    def overlaps(self, other: Span) -> bool:
        return self.start < other.end and other.start < self.end


@dataclass(frozen=True)
class Doc:
    uid: str
    text: str
    gold: tuple[Span, ...]
    tags: tuple[tuple[str, str], ...] = ()  # e.g. (("locale", "us"),): slice keys, never content
    dropped: tuple[str, ...] = ()  # labels of gold spans left out because they lie outside the text


BatchRun = Callable[[Sequence[str]], list[list[Span]]]


@dataclass(frozen=True)
class System:
    """A detector under test: spans per text, labelled with canonical types."""

    name: str
    claimed: frozenset[str]  # canonical types it is meant to detect (its scope)
    run: BatchRun
    config: Mapping[str, str] = field(default_factory=dict)  # versions and settings, for the report


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
        exact_r = self.found_overlap / self.support if self.support else None
        exact_p = self.pred_typed / self.predicted if self.predicted else None
        return {
            "support": self.support,
            "found_overlap": self.found_overlap,
            "found_strict": self.found_strict,
            "recall_overlap": r,
            "recall_strict": ratio(self.found_strict, self.support),
            "predicted": self.predicted,
            "pred_typed": self.pred_typed,
            "pred_any_label": self.pred_any,
            "precision_typed": p,
            "precision_any_label": ratio(self.pred_any, self.predicted),
            "f1_overlap": round(2 * exact_r * exact_p / (exact_r + exact_p), 4)  # from unrounded ratios
            if exact_r is not None and exact_p is not None and exact_r + exact_p
            else None,
        }


@dataclass
class Scorer:
    label_map: Mapping[str, str]
    compatible: Mapping[str, frozenset[str]] = field(default_factory=dict)  # type -> extra gold labels
    claimed: frozenset[str] | None = None  # the system's scope; None = every mapped type
    label_prefixes: Mapping[str, str] = field(default_factory=dict)  # label prefix -> type
    compatible_prefixes: Mapping[str, tuple[str, ...]] = field(default_factory=dict)  # type -> prefixes
    docs: int = 0
    by_type: dict[str, TypeCounts] = field(default_factory=lambda: defaultdict(TypeCounts))
    by_label: dict[str, Counter[str]] = field(default_factory=lambda: defaultdict(Counter))
    confusion: dict[str, Counter[str]] = field(default_factory=lambda: defaultdict(Counter))
    by_slice: dict[str, dict[str, TypeCounts]] = field(
        default_factory=lambda: defaultdict(lambda: defaultdict(TypeCounts))
    )
    dropped: Counter[str] = field(default_factory=Counter)

    def maps_to(self, label: str) -> str | None:
        if label in self.label_map:
            return self.label_map[label]
        return next((t for p, t in self.label_prefixes.items() if label.startswith(p)), None)

    def _typed_match(self, pred: Span, gold: Span) -> bool:
        return (
            self.maps_to(gold.label) == pred.label
            or gold.label in self.compatible.get(pred.label, frozenset())
            or gold.label.startswith(self.compatible_prefixes.get(pred.label, ()))
        )

    def add(self, doc: Doc, predicted: Iterable[Span]) -> None:
        preds = list(predicted)
        self.docs += 1
        self.dropped.update(doc.dropped)
        slices = [self.by_slice[f"{k}={v}"] for k, v in doc.tags]
        for g in doc.gold:
            covered = any(p.overlaps(g) for p in preds)
            lab = self.by_label[g.label]
            lab["support"] += 1
            lab["covered_any_type"] += covered
            t = self.maps_to(g.label)
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
        mapped = set(self.label_map.values()) | set(self.label_prefixes.values())

        def micro(types: Iterable[str]) -> dict[str, Any]:
            m = TypeCounts()
            for t in types:
                c = self.by_type.get(t, TypeCounts())
                m.support += c.support
                m.found_overlap += c.found_overlap
                m.found_strict += c.found_strict
                m.predicted += c.predicted
                m.pred_typed += c.pred_typed
                m.pred_any += c.pred_any
            return m.as_dict()

        claimed = mapped if self.claimed is None else mapped & self.claimed
        gold_total = sum(c["support"] for c in self.by_label.values())
        covered_total = sum(c["covered_any_type"] for c in self.by_label.values())
        # Present only when a dataset drops spans, so reports on strict datasets keep their form.
        dropped = {"gold_dropped_out_of_range": dict(sorted(self.dropped.items()))} if self.dropped else {}
        prefixes = (  # likewise only for datasets that map by prefix
            {
                "label_prefixes": dict(sorted(self.label_prefixes.items())),
                "compatible_prefixes": {k: list(v) for k, v in sorted(self.compatible_prefixes.items())},
            }
            if self.label_prefixes or self.compatible_prefixes
            else {}
        )
        return {
            "docs": self.docs,
            **dropped,
            "label_map": dict(sorted(self.label_map.items())),
            "compatible": {k: sorted(v) for k, v in sorted(self.compatible.items())},
            **prefixes,
            "by_type": {t: self.by_type[t].as_dict() for t in sorted(self.by_type)},
            "claimed_types": sorted(claimed),
            "micro_claimed_types": micro(sorted(claimed)),
            "micro_all_mapped_types": micro(sorted(mapped)),
            "any_type_coverage_all_labels": {
                "gold_spans": gold_total,
                "covered": covered_total,
                "rate": round(covered_total / gold_total, 4) if gold_total else None,
            },
            "by_label": {
                label: {
                    "support": c["support"],
                    "maps_to": self.maps_to(label),
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

    def q(a: int, b: int, stored: float | None) -> float | None:
        # From the counts: the stored ratio is rounded to 4 places, and rounding it again to 3 can
        # move the last digit (0.99447 -> 0.9945 -> 0.995).
        return a / b if b else stored

    def ratios(c: Mapping[str, Any]) -> tuple[float | None, ...]:
        if "pred_typed" not in c:  # a report written before the raw counts were added
            keys = ("recall_overlap", "recall_strict", "precision_typed", "precision_any_label", "f1_overlap")
            return tuple(c[k] for k in keys)
        r = q(c["found_overlap"], c["support"], c["recall_overlap"])
        p = q(c["pred_typed"], c["predicted"], c["precision_typed"])
        f1 = 2 * r * p / (r + p) if r is not None and p is not None and r + p else None
        return (
            r,
            q(c["found_strict"], c["support"], c["recall_strict"]),
            p,
            q(c["pred_any_label"], c["predicted"], c["precision_any_label"]),
            f1,
        )

    rows = [
        *report["by_type"].items(),
        ("micro†", report["micro_claimed_types"]),
        ("micro‡", report["micro_all_mapped_types"]),
    ]
    w = max(8, *(len(t) for t, _ in rows))
    lines = [
        f"{'type':<{w}} {'support':>8} {'R_overlap':>9} {'R_strict':>9} {'pred':>7} {'P_typed':>8} "
        f"{'P_any':>7} {'F1':>7}"
    ]
    for t, c in rows:
        r, rs, p, pa, f1 = ratios(c)
        lines.append(
            f"{t:<{w}} {c['support']:>8} {f(r):>9} {f(rs):>9} "
            f"{c['predicted']:>7} {f(p):>8} {f(pa):>7} {f(f1):>7}"
        )
    cov = report["any_type_coverage_all_labels"]
    cov_rate = q(cov["covered"], cov["gold_spans"], cov["rate"])
    m = max(8, *(len(c["maps_to"] or "") for c in report["by_label"].values()))
    lines += [
        "  † micro over the system's claimed types that dataset labels map to: "
        + ", ".join(report["claimed_types"]),
        "  ‡ micro over every type that dataset labels map to (same denominator for every system)",
        "",
        f"any-type coverage, all {len(report['by_label'])} dataset labels: "
        f"{cov['covered']}/{cov['gold_spans']} = {f(cov_rate).strip()}",
        *(
            [f"gold spans dropped (outside their text, not scored): {d}"]
            if (d := report.get("gold_dropped_out_of_range"))
            else []
        ),
        "",
        f"{'dataset label':<32} {'support':>8} {'maps_to':>{m}} {'covered':>8}",
    ]
    for label, c in sorted(report["by_label"].items(), key=lambda kv: -kv[1]["coverage_any_type"]):
        lines.append(
            f"{label:<32} {c['support']:>8} {c['maps_to'] or '-':>{m}} "
            f"{f(q(c['covered_any_type'], c['support'], c['coverage_any_type'])):>8}"
        )
    lines += ["", "system spans by overlapped gold label (top 6 per type):"]
    for t, c in report["confusion"].items():
        top = sorted(c.items(), key=lambda kv: -kv[1])[:6]
        lines.append(f"  {t:<{w}} " + ", ".join(f"{k} {v}" for k, v in top))
    return "\n".join(lines)

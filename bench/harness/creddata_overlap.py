"""PPE's secret rules against secret scanners on CredData, with and without its largest file: counts only.

    .venv/bin/python bench/harness/creddata_overlap.py <data-dir> <out.txt> <name>=<spans.jsonl> ...

Spans come from secret_scanner_spans.py. Two parts:

1. SECRET recall and typed precision for every system, scored by the same `Scorer` as `ppe evaluate
   run`, on all files and again without the file that holds the most T labels (one test file holds
   18% of them, so it can decide a comparison on its own).
2. T labels by who finds them, PPE and each scanner (overlap, as the Scorer counts it), split by value
   prefix as in creddata_secret_breakdown.py: what each adds to the other and what their union finds.

Never prints a value or a path.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

from creddata_secret_breakdown import _SECRET_PREFIX

from prompt_privacy.core.types import EntityType
from prompt_privacy.detectors.base import detect
from prompt_privacy.evaluation import datasets, scoring


def read(path: Path) -> dict[str, list[tuple[int, int]]]:
    out = {}
    for line in path.read_text().splitlines():
        row = json.loads(line)
        out[row["file"]] = [(s, e) for s, e, _ in row["spans"]]
    return out


def main() -> None:
    data_dir, dest = Path(sys.argv[1]), Path(sys.argv[2])
    scanners = {k: read(Path(v)) for k, v in (a.split("=", 1) for a in sys.argv[3:])}
    ds = datasets.CREDDATA
    path = datasets.verify(ds, data_dir, "all")
    names = ["PPE", *scanners]

    def scorer() -> scoring.Scorer:
        return scoring.Scorer(
            ds.label_map, ds.compatible, frozenset({"SECRET"}), ds.label_prefixes, ds.compatible_prefixes
        )

    # The largest file by T labels, found from the labels alone before any system is scored.
    t_count = {d.uid: sum(g.label.startswith("T:") for g in d.gold) for d in datasets.load(ds, path)}
    largest = max(t_count, key=lambda u: (t_count[u], u))
    full = {n: scorer() for n in names}
    rest = {n: scorer() for n in names}
    who: dict[str, Counter[tuple[str, str]]] = {n: Counter() for n in scanners}
    for doc in datasets.load(ds, path):
        spans = {"PPE": [(f.start, f.end) for f in detect(doc.text) if f.type is EntityType.SECRET]}
        spans.update({n: s.pop(doc.uid) for n, s in scanners.items()})
        for n in names:
            pred = [scoring.Span(s, e, "SECRET") for s, e in spans[n]]
            full[n].add(doc, pred)
            if doc.uid != largest:
                rest[n].add(doc, pred)
        for g in doc.gold:
            if not g.label.startswith("T:"):
                continue
            kind = "vendor prefix" if _SECRET_PREFIX.match(doc.text[g.start : g.end]) else "other value"
            hit = {n: any(s < g.end and g.start < e for s, e in spans[n]) for n in names}
            for n in scanners:
                a, b = hit["PPE"], hit[n]
                by = "both" if a and b else "PPE only" if a else f"{n} only" if b else "neither"
                who[n][(kind, by)] += 1
    if any(scanners.values()):
        raise SystemExit("span files that are not CredData documents")

    out = [
        f"creddata all @ {ds.revision[:12]}: SECRET, PPE rules and {', '.join(scanners)}",
        f"(the largest file holds {t_count[largest]} of {sum(t_count.values())} T labels)",
        "",
        f"{'system':<16} {'files':<22} {'support':>7} {'found':>6} {'R':>6}"
        f" {'spans':>6} {'typed':>6} {'P':>6}",
    ]
    for n in names:
        for label, sc in (("all", full[n]), ("without the largest", rest[n])):
            c = sc.report()["by_type"]["SECRET"]
            r = c["found_overlap"] / c["support"]
            p = c["pred_typed"] / c["predicted"] if c["predicted"] else float("nan")
            out.append(
                f"{n:<16} {label:<22} {c['support']:>7} {c['found_overlap']:>6} {r:6.3f}"
                f" {c['predicted']:>6} {c['pred_typed']:>6} {p:6.3f}"
            )
    for n in scanners:
        whos = ("both", "PPE only", f"{n} only", "neither")
        out += ["", f"T labels by who finds them, PPE rules vs {n}"]
        for kind in ("vendor prefix", "other value", "all"):
            row = {w: sum(c for (k, x), c in who[n].items() if x == w and kind in (k, "all")) for w in whos}
            total = sum(row.values())
            union = total - row["neither"]
            out.append(f"  {kind:<14} " + "  ".join(f"{w} {row[w]:>6}" for w in whos))
            out.append(f"  {'':<14} total {total}, union finds {union} ({union / total:.3f})")
    text = "\n".join(out) + "\n"
    dest.write_text(text)
    print(text)


if __name__ == "__main__":
    main()

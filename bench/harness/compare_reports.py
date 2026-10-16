"""Head-to-head of `ppe evaluate run --json` reports on the same dataset: counts and ratios only.

    .venv/bin/python bench/harness/compare_reports.py OUT.txt REPORT.json [REPORT.json ...]

Shared types are the types every system claims that dataset labels map to; the micro over them is
rebuilt from each report's raw counts, so every system is averaged over the same gold spans. Each
system's own-scope micro (†) and all-mapped micro (‡) and the per-label any-type coverage follow.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

COUNTS = ("support", "found_overlap", "found_strict", "predicted", "pred_typed", "pred_any_label")


def ratio(a: int, b: int) -> float | None:
    return a / b if b else None


def f(x: float | None) -> str:
    return "   n/a" if x is None else f"{x:6.3f}"


def summary(c: dict[str, int]) -> tuple[float | None, float | None, float | None, float | None]:
    r, rs = ratio(c["found_overlap"], c["support"]), ratio(c["found_strict"], c["support"])
    p = ratio(c["pred_typed"], c["predicted"])
    f1 = 2 * r * p / (r + p) if r is not None and p is not None and r + p else None
    return r, rs, p, f1


def name(rep: dict[str, Any]) -> str:
    s = rep["system"]
    extra = [f"phone={s['phone_context']}"] if "phone_context" in s else []
    return " ".join([s["name"], *extra, f"min={s['min_score']:g}"])


def main() -> None:
    out, paths = Path(sys.argv[1]), [Path(p) for p in sys.argv[2:]]
    reps = [json.loads(p.read_text()) for p in paths]
    ds = {(r["dataset"]["name"], r["dataset"]["revision"], r["dataset"]["split"], r["limit"]) for r in reps}
    if len(ds) != 1:
        sys.exit(f"reports are not on the same dataset, revision, split and limit: {sorted(ds)}")
    for r in reps:
        missing = [k for k in COUNTS if k not in r["micro_claimed_types"]]
        if missing:
            sys.exit(f"{name(r)}: report has no raw counts {missing}; re-run with the current scorer")
    names = [name(r) for r in reps]
    shared = sorted(set.intersection(*(set(r["claimed_types"]) for r in reps)))
    ((dname, rev, split, limit),) = ds
    lines = [
        f"{dname} {split} @ {rev[:12]} (limit={limit}); {len(reps)} reports",
        *(f"  [{i}] {n}  ({p.name})" for i, (n, p) in enumerate(zip(names, paths, strict=True))),
        "",
        "shared claimed types: " + ", ".join(shared),
        "",
        f"{'type':<14} {'sys':>3} {'support':>8} {'R_overlap':>9} {'R_strict':>9} {'pred':>8} "
        f"{'P_typed':>8} {'F1':>7}",
    ]
    for t in [*shared, "micro(shared)"]:
        for i, r in enumerate(reps):
            if t == "micro(shared)":
                c = {k: sum(r["by_type"].get(s, {}).get(k, 0) for s in shared) for k in COUNTS}
            else:
                c = {k: r["by_type"].get(t, {}).get(k, 0) for k in COUNTS}
            rr, rs, p, f1 = summary(c)
            lines.append(
                f"{t if i == 0 else '':<14} {i:>3} {c['support']:>8} {f(rr):>9} {f(rs):>9} "
                f"{c['predicted']:>8} {f(p):>8} {f(f1):>7}"
            )
    lines += ["", f"{'own scope / all mapped':<34} {'R':>6} {'P':>6} {'F1':>6}"]
    for i, r in enumerate(reps):
        for key, mark in (("micro_claimed_types", "†"), ("micro_all_mapped_types", "‡")):
            rr, _, p, f1 = summary({k: r[key][k] for k in COUNTS})
            lines.append(f"  [{i}] micro{mark} {'':<23} {f(rr)} {f(p)} {f(f1)}")
    lines += [
        "",
        "any-type coverage (protection view): "
        + "  ".join(f"[{i}] {r['any_type_coverage_all_labels']['rate']:.3f}" for i, r in enumerate(reps)),
        "",
    ]
    labels = sorted(reps[0]["by_label"])
    lines.append(
        f"{'dataset label':<30} {'support':>8} " + " ".join(f"{f'[{i}]':>6}" for i in range(len(reps)))
    )
    for label in sorted(labels, key=lambda lb: -max(r["by_label"][lb]["coverage_any_type"] for r in reps)):
        lines.append(
            f"{label:<30} {reps[0]['by_label'][label]['support']:>8} "
            + " ".join(f(r["by_label"][label]["coverage_any_type"]) for r in reps)
        )
    text = "\n".join(lines) + "\n"
    out.write_text(text)
    print(text)


if __name__ == "__main__":
    main()

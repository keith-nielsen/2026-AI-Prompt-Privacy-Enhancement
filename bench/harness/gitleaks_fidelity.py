"""Do PPE's imported Gitleaks rules find what Gitleaks finds? CredData, counts only.

    .venv/bin/python bench/harness/gitleaks_fidelity.py <data-dir> <gitleaks.jsonl> <out.txt>

Runs `prompt_privacy.detectors.gitleaks.find` (the rules alone: no PPE rules, no overlap
resolution) on every labelled file and compares its spans with Gitleaks' own (from
secret_scanner_spans.py) by rule: same span, overlapping span, or found by one side only.
Expected differences: rules that need a file path (skipped by PPE), Gitleaks' decoding of base64,
hex and percent-encoded text (PPE does not decode), Gitleaks reading a large file in fragments (its
keyword prefilter then sees one fragment, PPE the whole text), and the converter's line-only spans.
Never prints a value or a path.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

from prompt_privacy.detectors import gitleaks
from prompt_privacy.evaluation import datasets


def main() -> None:
    data_dir, spans_file, dest = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
    ds = datasets.CREDDATA
    path = datasets.verify(ds, data_dir, "all")
    theirs: dict[str, list[tuple[int, int, str]]] = {}
    for line in spans_file.read_text().splitlines():
        row = json.loads(line)
        theirs[row["file"]] = [(s, e, r) for s, e, r in row["spans"]]
    by_rule: Counter[tuple[str, str]] = Counter()
    for doc in datasets.load(ds, path):
        ours = gitleaks.find(doc.text)
        other = theirs.pop(doc.uid)
        for s, e, r in ours:
            if (s, e, r) in other:
                by_rule[(r, "same")] += 1
            elif any(r == r2 and s < e2 and s2 < e for s2, e2, r2 in other):
                by_rule[(r, "overlap")] += 1
            else:
                by_rule[(r, "PPE only")] += 1
        for s, e, r in other:
            if not any(r == r2 and s < e2 and s2 < e for s2, e2, r2 in ours):
                by_rule[(r, "Gitleaks only")] += 1
    if theirs:
        raise SystemExit(f"{len(theirs)} span files are not CredData documents")
    kinds = ("same", "overlap", "PPE only", "Gitleaks only")
    total = {k: sum(n for (_, x), n in by_rule.items() if x == k) for k in kinds}
    rs = gitleaks.rule_set()
    out = [
        f"creddata all @ {ds.revision[:12]}: PPE's Gitleaks {gitleaks.GITLEAKS_VERSION} rules"
        " vs Gitleaks itself",
        f"rules loaded {len(rs.rules)}, skipped (need a file path) {len(rs.skipped)}:"
        f" {', '.join(rs.skipped)}",
        "",
        "total  " + "  ".join(f"{k} {total[k]}" for k in kinds),
        "",
        "rules with any difference",
    ]
    for r in sorted({r for r, _ in by_rule}):
        row = {k: by_rule[(r, k)] for k in kinds}
        if row["overlap"] or row["PPE only"] or row["Gitleaks only"]:
            out.append(f"  {r:<34} " + "  ".join(f"{k} {row[k]:>5}" for k in kinds))
    text = "\n".join(out) + "\n"
    dest.write_text(text)
    print(text)


if __name__ == "__main__":
    main()

"""Check that result files hold no text from a pinned dataset before they are committed.

    .venv/bin/python bench/harness/leak_scan.py <data-dir> FILE [FILE ...]

Two searches over the dataset's test split:
1. every distinct gold value of 4+ characters, as a substring of each file;
2. any run of 35+ characters of document text: 24-character windows of each document, taken every
   12 characters, looked up among all 24-character substrings of the files (any shared run of 35 or
   more characters contains one such window). The dataset's label names are masked in the files
   first (the published schema, named by every report), and windows with fewer than 8 distinct
   characters (column padding, rules) are not counted.
Matches from (1) are printed with their shape so coincidences (counts, label names) can be told
apart; they are already in the files, so printing them adds nothing. Exit 1 if (2) finds anything.
"""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

from prompt_privacy.evaluation import datasets

DS = datasets.NEMOTRON_PII
W, STRIDE = 24, 12


def kind(v: str) -> str:
    if v.isdigit():
        return "digits"
    if v.replace("_", "").isalpha() and v.lower() == v:
        return "lowercase word"
    return "other"


def main() -> None:
    data_dir, files = Path(sys.argv[1]), [Path(p) for p in sys.argv[2:]]
    texts = {f: f.read_text() for f in files}
    path = datasets.verify(DS, data_dir, "test")
    values: set[str] = set()
    labels: set[str] = set()
    docs: list[str] = []
    for doc in datasets.load(DS, path, None):
        docs.append(doc.text)
        labels.update(g.label for g in doc.gold)
        values.update(v for g in doc.gold if len(v := doc.text[g.start : g.end]) >= 4)
    # The label names are the dataset's published schema and every report names them; some documents
    # are structured records keyed by them. Mask them before the run search.
    masked = dict(texts)
    for label in sorted(labels, key=len, reverse=True):
        masked = {f: t.replace(label, "\0") for f, t in masked.items()}
    shingles = {t[i : i + W] for t in masked.values() for i in range(len(t) - W + 1)}
    runs: Counter[str] = Counter()
    for t in docs:
        windows = (t[i : i + W] for i in range(0, len(t) - W + 1, STRIDE))
        runs.update(w for w in windows if w in shingles and len(set(w)) >= 8)  # not padding or rules
    print(
        f"{len(docs)} documents, {len(values)} distinct gold values (4+ chars), {len(files)} files; "
        f"{len(labels)} label names masked for the run search"
    )
    hits: Counter[tuple[str, str]] = Counter()
    by_len: dict[int, set[str]] = {}
    for v in values:
        by_len.setdefault(len(v), set()).add(v)
    for f, t in texts.items():
        for n, vs in by_len.items():
            if n <= 64:  # all substrings of length n, intersected with the values of that length
                found = vs & {t[i : i + n] for i in range(len(t) - n + 1)}
            else:
                found = {v for v in vs if v in t}
            for v in found:
                hits[(f.name, v)] += 1
    by_kind = Counter(kind(v) for _, v in hits)
    print(f"gold values found in the files: {len(hits)} ({dict(by_kind)})")
    for (name, v), _ in sorted(hits.items()):
        print(f"  {name}: {v!r} [{kind(v)}]")
    print(
        f"document windows sharing a run of {W + STRIDE - 1}+ chars with the files: "
        f"{sum(runs.values())} ({len(runs)} distinct)"
    )
    for w, n in runs.most_common():  # already in the files: printing it adds nothing
        print(f"  {n:>6}x {w!r} in " + ", ".join(f.name for f, t in masked.items() if w in t))
    sys.exit(1 if runs else 0)


if __name__ == "__main__":
    main()

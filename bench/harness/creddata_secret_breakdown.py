"""Where SECRET spans land on CredData, and which credentials they miss: counts only.

    .venv/bin/python bench/harness/creddata_secret_breakdown.py <data-dir> <out.txt> [spans.jsonl name]

Spans are PPE's (its secret rules), or a scanner's from secret_scanner_spans.py. Each span is put in
one class, in this order: on a T label (a hit), on an F label (reviewed, not a credential), on an X
label (undecided), on no label. Spans that are not hits are counted by rule and by a shape class of
their value (placeholder word, template or variable, few distinct characters, other). T labels are
counted found or missed by value prefix (one PPE has a rule for, as in miss_shapes.py, or not) and
missed ones by rule-name group. Never prints a value or a path.
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path

from prompt_privacy.core.types import EntityType
from prompt_privacy.detectors.base import detect
from prompt_privacy.evaluation import datasets

_PLACEHOLDER = re.compile(
    r"change|example|sample|dummy|test|fake|passw|secret|your|xxx|placeholder|todo|foo|bar|1234|abcd",
    re.IGNORECASE,
)
_TEMPLATE = re.compile(r"\$\{|\{\{|%\(|^<|>$|^\$|environ|getenv|process\.env|^%")
_GENERIC = ("Key", "Password", "Token", "Auth")
_SECRET_PREFIX = re.compile(  # as miss_shapes.py: vendor prefixes PPE has a rule for
    r"^(?:AKIA|ASIA|gh[pousr]_|github_pat_|sk-ant-|sk-|xox[abposr]-|AIza|[sr]k_(?:live|test)_|eyJ|-----BEGIN)"
)


def shape(v: str) -> str:
    if len(set(v)) <= 3:
        return "few-distinct-chars"
    if _TEMPLATE.search(v):
        return "template-or-variable"
    if _PLACEHOLDER.search(v):
        return "placeholder-word"
    return "other"


def main() -> None:
    data_dir, dest = Path(sys.argv[1]), Path(sys.argv[2])
    ds = datasets.CREDDATA
    path = datasets.verify(ds, data_dir, "all")
    name, external = "PPE", None
    if len(sys.argv) > 3:
        name = sys.argv[4]
        external = {}
        for line in Path(sys.argv[3]).read_text().splitlines():
            row = json.loads(line)
            external[row["file"]] = [(s, e, r) for s, e, r in row["spans"]]
    where: Counter[str] = Counter()
    rule: Counter[tuple[str, str]] = Counter()
    shapes: Counter[tuple[str, str]] = Counter()
    missed: Counter[str] = Counter()
    prefix: Counter[tuple[str, str]] = Counter()
    t_total = t_missed = 0
    for doc in datasets.load(ds, path):
        if external is None:
            found = [(f.start, f.end, f.subtype) for f in detect(doc.text) if f.type is EntityType.SECRET]
        else:
            found = external.pop(doc.uid)
        for start, end, sub in found:
            over = [g.label[0] for g in doc.gold if g.start < end and start < g.end]
            cls = next((c for c in "TFX" if c in over), "none")
            where[cls] += 1
            rule[(cls, sub)] += 1
            if cls != "T":
                shapes[(cls, shape(doc.text[start:end]))] += 1
        for g in doc.gold:
            if not g.label.startswith("T:"):
                continue
            t_total += 1
            kind = "vendor prefix" if _SECRET_PREFIX.match(doc.text[g.start : g.end]) else "other value"
            hit = any(start < g.end and g.start < end for start, end, _ in found)
            prefix[(kind, "found" if hit else "missed")] += 1
            if hit:
                continue
            t_missed += 1
            names = g.label[2:].split(":")
            missed["generic (Key/Password/Token/Auth)" if any(n in _GENERIC for n in names) else "other"] += 1
    out = [
        f"creddata all @ {ds.revision[:12]}: {name} SECRET spans by where they land (each span in one class)",
        *(f"  {c:<6} {n:>7}" for c, n in sorted(where.items())),
        "",
        "by class and secret rule",
        *(f"  {c:<6} {r:<26} {n:>7}" for (c, r), n in sorted(rule.items())),
        "",
        "spans that are not hits, by value shape",
        *(f"  {c:<6} {s:<22} {n:>7}" for (c, s), n in sorted(shapes.items())),
        "",
        "T labels found, by value prefix (vendor prefix: one PPE has a rule for)",
        *(
            f"  {k:<14} {prefix[(k, 'found')]:>6} / {prefix[(k, 'found')] + prefix[(k, 'missed')]:>6}"
            for k in ("vendor prefix", "other value")
        ),
        "",
        f"T labels {t_total}, missed {t_missed}",
        *(f"  {k:<36} {n:>7}" for k, n in sorted(missed.items())),
    ]
    if external:
        raise SystemExit(f"{len(external)} span files are not CredData documents")
    text = "\n".join(out) + "\n"
    dest.write_text(text)
    print(text)


if __name__ == "__main__":
    main()

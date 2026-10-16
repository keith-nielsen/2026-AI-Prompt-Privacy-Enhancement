"""Why PPE's rules miss a dataset's gold spans: shape classes of found and missed spans, counts only.

    .venv/bin/python bench/harness/miss_shapes.py <dataset> <data-dir> <out.txt> [limit]

Never prints a value: each gold span is reduced to a shape class (checksum valid, masked, digit
count, prefix family, ...), chosen by the canonical type its label maps to. Outputs: `miss_shapes.txt`
in bench/results/2026-10-16-nemotron-pii/ and bench/results/2026-10-16-gretel-pii-finance/.
"""

from __future__ import annotations

import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

from prompt_privacy.core.checksums import iban_valid, luhn_valid
from prompt_privacy.detectors.base import detect
from prompt_privacy.evaluation import datasets

_SECRET_PREFIX = re.compile(
    r"^(?:AKIA|ASIA|gh[pousr]_|github_pat_|sk-ant-|sk-|xox[abposr]-|AIza|[sr]k_(?:live|test)_|eyJ|-----BEGIN)"
)


_SHAPED = frozenset({"CARD", "IPV4", "IPV6", "SECRET", "PHONE", "EMAIL", "IBAN"})  # types PPE's rules claim


def shape(t: str, v: str) -> str:
    d = "".join(c for c in v if c.isdigit())
    if t == "CARD":
        if re.search(r"[*xX•#]", v):
            return "masked"
        if not 13 <= len(d) <= 19:
            return f"digits={len(d)}"
        return "luhn-valid" if luhn_valid(d) else "luhn-invalid"
    if t == "IPV4":
        if re.search(r":\d+$", v):
            return "with-port"
        if "/" in v:
            return "cidr"
        if any(len(o) > 1 and o.startswith("0") for o in v.split(".")):
            return "leading-zero"
        return "plain" if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", v) else "other"
    if t == "IPV6":
        return "cidr" if "/" in v else ("bracketed" if v.startswith("[") else "plain")
    if t == "SECRET":
        if _SECRET_PREFIX.match(v):
            return "vendor-prefix"
        return f"generic-len{min(len(v) // 16 * 16, 64)}+"
    if t == "PHONE":
        ext = bool(re.search(r"(?i)\b(?:x|ext\.?)\s*\d", v))
        plus = v.lstrip().startswith("+")
        return f"{'intl+' if plus else 'national'}{',ext' if ext else ''},digits={min(len(d), 16)}"
    if t == "EMAIL":
        return "plain" if "@" in v else "no-at"
    if t == "IBAN":
        c = "".join(v.split())
        grouped = "grouped" if " " in v.strip() else "compact"
        return f"{'mod97-valid' if iban_valid(c) else 'mod97-invalid'},{grouped}"
    return "-"


def main() -> None:
    ds = datasets.DATASETS[sys.argv[1]]
    data_dir, dest = Path(sys.argv[2]), Path(sys.argv[3])
    limit = int(sys.argv[4]) if len(sys.argv) > 4 else None
    path = datasets.verify(ds, data_dir, "test")
    counts: dict[str, Counter[str]] = defaultdict(Counter)
    for doc in datasets.load(ds, path, limit):
        found = detect(doc.text)
        for g in doc.gold:
            t = ds.label_map.get(g.label)
            if t is None or t not in _SHAPED:
                continue
            hit = any(f.type.value == t and f.start < g.end and g.start < f.end for f in found)
            counts[g.label][f"{shape(t, doc.text[g.start : g.end])} {'found' if hit else 'MISSED'}"] += 1
    out = [f"shape classes of mapped gold spans ({ds.name} test, limit={limit}, phone_context=optional)"]
    for label in sorted(counts):
        c = counts[label]
        out.append(f"\n{label} ({sum(c.values())})")
        out += [f"  {k:<40} {n:>7}" for k, n in sorted(c.items(), key=lambda kv: -kv[1])]
    text = "\n".join(out) + "\n"
    dest.write_text(text)
    print(text)


if __name__ == "__main__":
    main()

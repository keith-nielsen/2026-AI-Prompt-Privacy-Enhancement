"""Placeholder filters for PPE's `assignment` (KEY=value) rule, side by side on the same spans: counts only.

    .venv/bin/python bench/harness/assignment_filters.py <data-dir> <out.txt>

Every `assignment` span PPE's rules would report with no filter is judged by each filter; kept spans
are counted by CredData label class (T, F, X, no label) and, on Nemotron and Gretel, by gold label
(`password`, `api_key`, ...). Filters: none; Gitleaks' 1,448 stop words (secret rules v2,
v0.1.0.dev2); a short placeholder list with template and code checks; that list plus words naming a
kind of credential (v3, shipped: `secrets.is_placeholder`); v3 plus "an unquoted letters-only value is
an identifier" (rejected). Four worker processes (CredData in two halves, Nemotron, Gretel), cores as
the caller pins them. Never prints a value or a path.
"""

from __future__ import annotations

import multiprocessing
import re
import sys
from collections import Counter
from pathlib import Path

from prompt_privacy.detectors import gitleaks
from prompt_privacy.detectors.secrets import PLACEHOLDER_WORDS, RULES_VERSION, SECRET_RULES, is_placeholder
from prompt_privacy.evaluation import datasets

_RX = dict(SECRET_RULES)["assignment"]
_GL_WORDS: tuple[str, ...] = ()
_TEMPLATE = re.compile(r"^\$[A-Za-z_{(]|^%\(|^%[A-Za-z_]+%$|^<[^>]*>$|\$\{|\{\{|\}\}|#\{")


def _gitleaks_words() -> tuple[str, ...]:
    rs = gitleaks.rule_set()
    generic = next(r for r in rs.rules if r.id == "generic-api-key")
    return tuple(sorted({w for a in (*rs.allowlists, *generic.allowlists) for w in a.stopwords}))


def _short(v: str, quoted: bool) -> bool:
    low = v.lower()
    return (
        any(w in low for w in PLACEHOLDER_WORDS)
        or _TEMPLATE.search(v) is not None
        or len(set(v)) <= 3
        or (not quoted and re.search(r"[(\[]", v) is not None)
    )


FILTERS = {
    "none": lambda v, q: False,
    "Gitleaks stop words (v2)": lambda v, q: any(w in v.lower() for w in _GL_WORDS),
    "short list": _short,
    "short + credential kinds (v3)": is_placeholder,
    "v3 + letters-only (rejected)": lambda v, q: (
        is_placeholder(v, q) or (not q and re.fullmatch(r"[A-Za-z_.-]+", v) is not None)
    ),
}


def _part(job: tuple[str, Path]) -> tuple[str, Counter[tuple[str, str]]]:
    part, data_dir = job
    global _GL_WORDS
    _GL_WORDS = _gitleaks_words()
    name = "creddata" if part.startswith("creddata") else part
    ds = datasets.DATASETS[name]
    out: Counter[tuple[str, str]] = Counter()
    docs = datasets.load(ds, datasets.verify(ds, data_dir, next(iter(ds.splits))))
    for i, doc in enumerate(docs):
        if name == "creddata" and i % 2 != int(part[-1]):
            continue
        for m in _RX.finditer(doc.text):
            s, e = m.span("s")
            value, quoted = doc.text[s:e], doc.text[s - 1 : s] in "\"'"
            over = [g.label for g in doc.gold if g.start < e and s < g.end]
            if name == "creddata":
                cls = next((c for c in "TFX" if any(o[0] == c for o in over)), "no label")
            else:
                cls = over[0] if over else "no gold"
            for f, drop in FILTERS.items():
                if not drop(value, quoted):
                    out[(f, cls)] += 1
    return name, out


def main() -> None:
    data_dir, dest = Path(sys.argv[1]), Path(sys.argv[2])
    jobs = [(p, data_dir) for p in ("creddata0", "creddata1", "nemotron-pii", "gretel-pii-finance")]
    totals: dict[str, Counter[tuple[str, str]]] = {}
    with multiprocessing.get_context("fork").Pool(3) as pool:
        for name, c in pool.imap_unordered(_part, jobs):
            totals.setdefault(name, Counter()).update(c)
    out = [f"`assignment` spans kept per filter (secret rules v{RULES_VERSION})"]
    for name, cols in (
        ("creddata", ("T", "F", "X", "no label")),
        ("nemotron-pii", ("password", "api_key", "no gold")),
        ("gretel-pii-finance", ("password", "api_key", "no gold")),
    ):
        out += ["", f"{name}: " + "  ".join(f"{c:>9}" for c in cols)]
        for f in FILTERS:
            out.append(f"  {f:<32}" + "  ".join(f"{totals[name][(f, c)]:>9}" for c in cols))
    text = "\n".join(out) + "\n"
    dest.write_text(text)
    print(text)


if __name__ == "__main__":
    main()

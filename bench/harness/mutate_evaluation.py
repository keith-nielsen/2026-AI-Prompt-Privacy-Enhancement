"""Negative proof for the evaluation harness and the stdnum cross-check: break one mechanism at a
time, run the tests, restore. Every mutation must make at least one test fail.

    .venv/bin/python bench/harness/mutate_evaluation.py   # from the repository root; restores every file
"""

import subprocess, sys, pathlib
M = [
 ("scoring: adjacency counts as overlap", "src/prompt_privacy/evaluation/scoring.py", "return self.start < other.end and other.start < self.end", "return self.start <= other.end and other.start <= self.end"),
 ("scoring: strict == overlap", "src/prompt_privacy/evaluation/scoring.py", "exact = any(p.label == t and p.start == g.start and p.end == g.end for p in preds)", "exact = hit"),
 ("scoring: compatible ignored", "src/prompt_privacy/evaluation/scoring.py", "or gold.label in self.compatible.get(", "and gold.label in self.compatible.get("),
 ("scoring: wrong type counts as found", "src/prompt_privacy/evaluation/scoring.py", "hit = any(p.label == t and p.overlaps(g) for p in preds)", "hit = covered"),
 ("fetch: hash not checked", "src/prompt_privacy/evaluation/datasets.py", "if n != size or h.hexdigest() != sha256:", "if n != size:"),
 ("fetch: size cap removed", "src/prompt_privacy/evaluation/datasets.py", "if n > size:", "if False:"),
 ("verify: hash not checked", "src/prompt_privacy/evaluation/datasets.py", "if got != ds.splits[split].sha256:", "if False:"),
 ("parse: bounds not checked", "src/prompt_privacy/evaluation/datasets.py", "if not 0 <= start < end <= text_len:", "if False:"),
 ("luhn: wrong position doubled", "src/prompt_privacy/core/checksums.py", "if i % 2 == 0:", "if i % 2 == 1:"),
 ("iban: check digits off by one", "src/prompt_privacy/core/checksums.py", 'return f"{98 - n % 97:02d}"', 'return f"{(99 - n % 97) % 100:02d}"'),
 ("iban surrogate: valid check digits", "src/prompt_privacy/core/surrogates.py", "bad = (valid + r.randint(1, 96)) % 100", "bad = valid"),
 ("detector: IPv4 full-stop fix reverted", "src/prompt_privacy/detectors/patterns.py", r'(?!\d|\.\d)")', r'(?![\d.])")'),
 ("detector: IBAN grouped form not matched", "src/prompt_privacy/detectors/patterns.py", r'(?:[ ]?[A-Za-z0-9]){11,30}', r'(?:[A-Za-z0-9]){11,30}'),
]
tests = ["tests/evaluation", "tests/unit/test_checksums_stdnum.py", "tests/detectors/test_patterns.py", "tests/unit/test_checksums.py"]
caught = 0
for name, path, old, new in M:
    p = pathlib.Path(path); src = p.read_text()
    assert src.count(old) == 1, (name, src.count(old))
    p.write_text(src.replace(old, new))
    try:
        r = subprocess.run([".venv/bin/pytest", "-q", "-x", "-p", "no:cacheprovider", *tests], capture_output=True, text=True)
    finally:
        p.write_text(src)
    killed = r.returncode != 0
    caught += killed
    failed = [l.split("::")[-1].split(" ")[0] for l in r.stdout.splitlines() if l.startswith("FAILED")]
    print(f"{'CAUGHT ' if killed else 'MISSED '} {name:<42} {failed[:1]}")
print(f"\n{caught}/{len(M)} mutations caught")

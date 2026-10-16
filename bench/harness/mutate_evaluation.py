"""Negative proof for the evaluation harness and the stdnum cross-check: break one mechanism at a
time, run the tests, restore. Every mutation must make at least one test fail.

    .venv/bin/python bench/harness/mutate_evaluation.py   # from the repository root; restores every file

Mutations marked "(presidio)" need real Presidio: run the script with bench/harness/pvenv/bin/python
and PPE_PRESIDIO_MODEL set to the local spaCy model directory (a model run, so under the usual cap);
otherwise they are reported as not run.
"""

import os, subprocess, sys, pathlib
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
 ("scoring: claimed scope ignored", "src/prompt_privacy/evaluation/scoring.py", "claimed = mapped if self.claimed is None else mapped & self.claimed", "claimed = mapped"),
 ("cli: score threshold not applied", "src/prompt_privacy/cli/main.py", "[s for s in spans if s.score >= t]", "list(spans)"),
 ("presidio: IPv6 labelled IPv4", "src/prompt_privacy/evaluation/systems.py", 'label = "IPV6" if ":" in text[r.start : r.end] else "IPV4"', 'label = "IPV4"'),
 ("presidio: model name accepted", "src/prompt_privacy/evaluation/systems.py", 'if not model_path.is_dir() or not (model_path / "meta.json").is_file():', "if False:"),
 ("presidio: suffix list fetched online (presidio)", "src/prompt_privacy/evaluation/systems.py", "suffix_list_urls=(), fallback_to_snapshot", 'suffix_list_urls=("http://127.0.0.1:9/psl.dat",), fallback_to_snapshot'),  # loopback, refused: no fetch leaves the host
 ("table: stored ratios rounded again", "src/prompt_privacy/evaluation/scoring.py", 'if "pred_typed" not in c:', "if True:"),
 ("scoring: F1 from rounded ratios", "src/prompt_privacy/evaluation/scoring.py", "round(2 * exact_r * exact_p / (exact_r + exact_p), 4)", "round(2 * r * p / (r + p), 4)"),
 ("detector: IPv6 allowed inside words", "src/prompt_privacy/detectors/patterns.py", r'_IPV6 = re.compile(r"(?<![\w:])', r'_IPV6 = re.compile(r"(?<![0-9A-Fa-f:])'),
 ("detector: IBAN not cut back to a valid prefix", "src/prompt_privacy/detectors/patterns.py", 'for end in [len(s), *(i for i in range(len(s) - 1, 0, -1) if s[i] == " ")]:', "for end in [len(s)]:"),
 ("detector: e-mail ASCII only", "src/prompt_privacy/detectors/patterns.py", r'(?:[^\W_]|[._%+-])+@(?:(?:[^\W_]|-)+\.)+[^\W\d_]{2,}', r'[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}'),
 ("datasets: out-of-range span silently dropped everywhere", "src/prompt_privacy/evaluation/datasets.py", 'dropped: list[str] | None = [] if ds.out_of_range == "drop" else None', "dropped: list[str] | None = []"),
 ("detector: IBAN grouped form not matched", "src/prompt_privacy/detectors/patterns.py", r'(?:[ ]?[A-Za-z0-9]){11,30}', r'(?:[A-Za-z0-9]){11,30}'),
]
tests = ["tests/evaluation", "tests/unit/test_checksums_stdnum.py", "tests/detectors/test_patterns.py", "tests/unit/test_checksums.py"]
try:
    import presidio_analyzer  # noqa: F401
    have_presidio = bool(os.environ.get("PPE_PRESIDIO_MODEL"))
except ImportError:
    have_presidio = False
cmd = [sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", *tests]
# Control: the unmutated tree must pass, or every "caught" below would only reflect a broken setup.
base = subprocess.run(cmd, capture_output=True, text=True)
if base.returncode != 0:
    sys.exit("control run failed on the unmutated tree:\n" + base.stdout[-2000:])
print("control  unmutated tree passes")
caught = run = 0
for name, path, old, new in M:
    if "(presidio)" in name and not have_presidio:
        print(f"NOT RUN  {name:<42} (needs Presidio and PPE_PRESIDIO_MODEL)")
        continue
    run += 1
    p = pathlib.Path(path); src = p.read_text()
    assert src.count(old) == 1, (name, src.count(old))
    p.write_text(src.replace(old, new))
    try:
        r = subprocess.run(cmd, capture_output=True, text=True)
    finally:
        p.write_text(src)
    killed = r.returncode != 0
    caught += killed
    # "FAILED path::test[param] - msg": the test's name only. A param may contain "::", and may hold a
    # sample identifier that does not belong in a committed result file (C-46).
    failed = [l[7:].split(" - ")[0].split("::", 1)[-1].split("[")[0] for l in r.stdout.splitlines() if l.startswith("FAILED")]
    print(f"{'CAUGHT ' if killed else 'MISSED '} {name:<42} {failed[:1]}")
print(f"\n{caught}/{run} mutations caught ({len(M) - run} not run)")

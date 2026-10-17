"""Turn Gitleaks or detect-secrets findings on CredData into character spans: offsets only, no values.

    # Gitleaks: convert its JSON report (run_secret_scanners.sh writes it, then deletes it)
    python3 -I bench/harness/secret_scanner_spans.py gitleaks <creddata-repo> <report.json> <out.jsonl>
    # detect-secrets: scan in-process, default plugins and filters (dsvenv = bench/harness/dsvenv)
    dsvenv/bin/python -I bench/harness/secret_scanner_spans.py detect-secrets <creddata-repo> <out.jsonl>

Standard library only (plus detect_secrets for its mode), so it runs in either venv and never imports
PPE. Each output line is {"file": "data/...", "spans": [[start, end, rule], ...]} for one labelled
file, with offsets into the text as `datasets.creddata_doc` reads it (UTF-8, line ends normalised to
\\n). A finding's value is looked up on its reported lines; when it is not there verbatim (a value the
tool rebuilt, e.g. from a YAML transform or across \\r\\n line ends), the span is the whole of those
lines and is counted as `line_only` in the summary (the last line on stderr, after progress lines).
detect-secrets scans with three worker processes. Values never leave this process.
"""

from __future__ import annotations

import csv
import json
import multiprocessing
import sys
from collections import Counter
from pathlib import Path
from typing import Any

_DS_SETTINGS: Any = None


def labelled_files(root: Path) -> list[str]:
    files: set[str] = set()
    for meta in sorted((root / "meta").glob("*.csv")):
        with meta.open(newline="", encoding="utf-8") as fh:
            files.update(r["FilePath"] for r in csv.DictReader(fh))
    return sorted(files)


class Lines:
    """A file's text as `creddata_doc` reads it, with line starts (lines numbered from 1)."""

    def __init__(self, raw: bytes) -> None:
        self.text = raw.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
        self.starts = [0] + [i + 1 for i, c in enumerate(self.text) if c == "\n"]

    def bounds(self, first: int, last: int) -> tuple[int, int] | None:
        if not 1 <= first <= last <= len(self.starts):
            return None
        end = self.starts[last] - 1 if last < len(self.starts) else len(self.text)
        return self.starts[first - 1], end

    def locate(self, value: str, first: int, last: int) -> tuple[int, int, bool] | None:
        """(start, end, exact): the value on lines first..last, else those whole lines."""
        b = self.bounds(first, last)
        if b is None:
            return None
        value = value.replace("\r\n", "\n").replace("\r", "\n")
        k = self.text.find(value, b[0], b[1]) if value else -1
        return (k, k + len(value), True) if k >= 0 else (b[0], b[1], False)


def emit(out: Path, spans: dict[str, list[list[object]]], files: list[str], tally: Counter[str]) -> None:
    with out.open("w") as fh:
        for rel in files:
            fh.write(json.dumps({"file": rel, "spans": sorted(spans.get(rel, []))}) + "\n")
    print(json.dumps(dict(sorted(tally.items()))), file=sys.stderr)


def from_gitleaks(root: Path, report: Path, out: Path) -> None:
    files = labelled_files(root)
    wanted = set(files)
    data = (root / "data").resolve()
    spans: dict[str, list[list[object]]] = {}
    texts: dict[str, Lines] = {}
    tally: Counter[str] = Counter()
    for f in json.loads(report.read_text()):
        rel = "data/" + Path(f["File"]).resolve().relative_to(data).as_posix()
        tally["findings"] += 1
        if rel not in wanted:
            tally["on_unlabelled_files"] += 1
            continue
        lines = texts.get(rel) or texts.setdefault(rel, Lines((root / rel).read_bytes()))
        hit = lines.locate(f["Secret"], f["StartLine"], f["EndLine"])
        if hit is None:
            tally["outside_text"] += 1
            continue
        tally["exact" if hit[2] else "line_only"] += 1
        spans.setdefault(rel, []).append([hit[0], hit[1], f["RuleID"]])
    emit(out, spans, files, tally)


def _ds_init() -> None:  # each worker process: all plugins, default filters, for its lifetime
    from detect_secrets.settings import default_settings

    global _DS_SETTINGS
    _DS_SETTINGS = default_settings()
    _DS_SETTINGS.__enter__()


def _ds_scan(job: tuple[Path, str]) -> tuple[str, list[list[object]], Counter[str]]:
    from detect_secrets.core.scan import scan_file

    root, rel = job
    spans: list[list[object]] = []
    tally: Counter[str] = Counter()
    lines = None
    for s in scan_file(str(root / rel)):
        tally["findings"] += 1
        lines = lines or Lines((root / rel).read_bytes())
        hit = lines.locate(s.secret_value or "", s.line_number, s.line_number)
        if hit is None:
            tally["outside_text"] += 1
            continue
        tally["exact" if hit[2] else "line_only"] += 1
        spans.append([hit[0], hit[1], s.type])
    return rel, spans, tally


def from_detect_secrets(root: Path, out: Path, workers: int = 3) -> None:
    files = labelled_files(root)
    spans: dict[str, list[list[object]]] = {}
    tally: Counter[str] = Counter()
    with multiprocessing.get_context("fork").Pool(workers, initializer=_ds_init) as pool:
        jobs = ((root, rel) for rel in files)
        for n, (rel, found, t) in enumerate(pool.imap_unordered(_ds_scan, jobs, chunksize=8), 1):
            if found:
                spans[rel] = found
            tally.update(t)
            if n % 500 == 0 or n == len(files):
                print(f"progress {n}/{len(files)}", file=sys.stderr, flush=True)
    emit(out, spans, files, tally)


def main() -> None:
    tool, root = sys.argv[1], Path(sys.argv[2])
    if tool == "gitleaks":
        from_gitleaks(root, Path(sys.argv[3]), Path(sys.argv[4]))
    elif tool == "detect-secrets":
        from_detect_secrets(root, Path(sys.argv[3]))
    else:
        raise SystemExit(f"unknown tool {tool!r}: gitleaks or detect-secrets")


if __name__ == "__main__":
    main()

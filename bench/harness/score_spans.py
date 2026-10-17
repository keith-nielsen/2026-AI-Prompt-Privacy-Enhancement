"""Score a secret scanner's CredData spans (secret_scanner_spans.py) like `ppe evaluate run`: counts only.

    .venv/bin/python bench/harness/score_spans.py <data-dir> <spans.jsonl> <name> <version> <out.json>

Every span is labelled SECRET, the scanner's whole scope. The report has the same form as
`ppe evaluate run --json`, so compare_reports.py and the write-up read it the same way.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from prompt_privacy.evaluation import datasets, scoring


def read_spans(path: Path) -> dict[str, list[scoring.Span]]:
    out: dict[str, list[scoring.Span]] = {}
    for line in path.read_text().splitlines():
        row = json.loads(line)
        out[row["file"]] = [scoring.Span(s, e, "SECRET") for s, e, _rule in row["spans"]]
    return out


def main() -> None:
    data_dir, spans_file, name, version, dest = sys.argv[1:6]
    ds = datasets.CREDDATA
    path = datasets.verify(ds, Path(data_dir), "all")
    spans = read_spans(Path(spans_file))
    sc = scoring.Scorer(
        ds.label_map, ds.compatible, frozenset({"SECRET"}), ds.label_prefixes, ds.compatible_prefixes
    )
    for doc in datasets.load(ds, path):
        sc.add(doc, spans.pop(doc.uid))
    if spans:
        raise SystemExit(f"{len(spans)} span files are not CredData documents")
    report = {
        "dataset": {
            "name": ds.name,
            "repo": ds.repo,
            "revision": ds.revision,
            "split": "all",
            "file_sha256": ds.splits["all"].sha256,
            "licence": ds.licence,
            "attribution": ds.attribution,
            "notes": list(ds.notes),
        },
        "system": {
            "name": name,
            "version": version,
            "configuration": "default rules and filters; offline (no network namespace), no verification",
            "min_score": 0.0,
        },
        "limit": None,
        **sc.report(),
    }
    Path(dest).write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    table = scoring.table(report)
    Path(dest).with_suffix(".txt").write_text(table + "\n")
    print(table)


if __name__ == "__main__":
    main()

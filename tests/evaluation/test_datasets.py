"""Dataset pinning, download checks and the Nemotron row parser, on synthetic local files only."""

import hashlib
import re
from dataclasses import replace
from pathlib import Path

import pytest

from prompt_privacy.evaluation import datasets
from prompt_privacy.evaluation.datasets import NEMOTRON_PII, DataFile, fetch_file, parse_spans, row_doc
from prompt_privacy.evaluation.scoring import CANONICAL_TYPES, Scorer, Span, table


def test_pins_are_exact() -> None:
    for ds in datasets.DATASETS.values():
        assert re.fullmatch(r"[0-9a-f]{40}", ds.revision), "pin a commit, never a branch"
        for f in ds.splits.values():
            assert re.fullmatch(r"[0-9a-f]{64}", f.sha256) and f.size > 0
            assert ds.url(f).startswith("https://huggingface.co/datasets/")
        assert set(ds.label_map.values()) <= CANONICAL_TYPES and set(ds.compatible) <= CANONICAL_TYPES


def test_parse_spans() -> None:
    raw = (
        "[{'start': 0, 'end': 5, 'text': 'Brian', 'label': 'first_name'},"
        " {'start': 6, 'end': 8, 'text': 42, 'label': 'age'}]"
    )
    assert parse_spans(raw, 10) == (Span(0, 5, "first_name"), Span(6, 8, "age"))


@pytest.mark.parametrize(
    "raw",
    [
        "[{'start': 0, 'end': 11, 'label': 'x'}]",  # past the end of the text
        "[{'start': 5, 'end': 5, 'label': 'x'}]",  # empty
        "[{'start': '0', 'end': 5, 'label': 'x'}]",  # wrong type
        "{'start': 0}",  # not a list
        "__import__('os').system('true')",  # code is never evaluated
    ],
)
def test_parse_spans_rejects(raw: str) -> None:
    with pytest.raises((ValueError, KeyError)):
        parse_spans(raw, 10)


def test_doc_keeps_only_slice_keys() -> None:
    row = {"uid": "a", "text": "hello", "spans": "[]", "locale": "us", "domain": "health"}
    d = row_doc(replace(NEMOTRON_PII, slice_keys=("locale",)), row)
    assert d.tags == (("locale", "us"),) and d.gold == ()


def _src(tmp_path: Path, data: bytes) -> tuple[str, str]:
    src = tmp_path / "src.bin"
    src.write_bytes(data)
    return src.as_uri(), hashlib.sha256(data).hexdigest()


def test_fetch_file_keeps_matching_download(tmp_path: Path) -> None:
    url, h = _src(tmp_path, b"abc" * 1000)
    dest = tmp_path / "out" / "f.bin"
    fetch_file(url, dest, h, 3000)
    assert dest.read_bytes() == b"abc" * 1000


@pytest.mark.parametrize(
    ("bad", "message"),
    [
        ("hash", "expected 3000"),
        ("source longer", "more than the expected"),  # aborted while streaming, not after
        ("source shorter", "got 3000 bytes"),
    ],
)
def test_fetch_file_leaves_nothing_on_mismatch(tmp_path: Path, bad: str, message: str) -> None:
    url, h = _src(tmp_path, b"abc" * 1000)
    dest = tmp_path / "out" / "f.bin"
    sha, size = {"hash": ("0" * 64, 3000), "source longer": (h, 2999), "source shorter": (h, 3001)}[bad]
    with pytest.raises(ValueError, match=message):
        fetch_file(url, dest, sha, size)
    assert list(dest.parent.iterdir()) == []


def test_verify_refuses_tampered_or_missing_file(tmp_path: Path) -> None:
    data = b"not parquet, but pinned"
    ds = replace(
        NEMOTRON_PII,
        splits={"test": DataFile("data/t.parquet", hashlib.sha256(data).hexdigest(), len(data))},
    )
    with pytest.raises(FileNotFoundError):
        datasets.verify(ds, tmp_path, "test")
    p = datasets.local_path(ds, tmp_path, "test")
    p.parent.mkdir(parents=True)
    p.write_bytes(data)
    assert datasets.verify(ds, tmp_path, "test") == p
    assert datasets.fetch(ds, tmp_path, "test") == p  # already present and matching: no download
    p.write_bytes(data + b"!")
    with pytest.raises(ValueError, match="not the pinned"):
        datasets.verify(ds, tmp_path, "test")


def test_load_reads_parquet(tmp_path: Path) -> None:
    pa = pytest.importorskip("pyarrow")
    pq = pytest.importorskip("pyarrow.parquet")
    rows = {
        "uid": ["a", "b", "c"],
        "text": ["mail x@y.test", "none", "ip 192.0.2.1"],
        "spans": [
            "[{'start': 5, 'end': 13, 'label': 'email'}]",
            "[]",
            "[{'start': 3, 'end': 12, 'label': 'ipv4'}]",
        ],
        "locale": ["us", "intl", "us"],
        "document_format": ["unstructured"] * 3,
    }
    path = tmp_path / "t.parquet"
    pq.write_table(pa.table(rows), path)
    docs = list(datasets.load(NEMOTRON_PII, path))
    assert [d.uid for d in docs] == ["a", "b", "c"]
    assert docs[0].gold == (Span(5, 13, "email"),)
    assert docs[1].tags == (("locale", "intl"), ("document_format", "unstructured"))
    assert len(list(datasets.load(NEMOTRON_PII, path, limit=2))) == 2


def test_cli_run_end_to_end(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """`ppe evaluate run` on a pinned stand-in file: scores, writes the report, and leaks no text."""
    import json

    pa = pytest.importorskip("pyarrow")
    pq = pytest.importorskip("pyarrow.parquet")
    from prompt_privacy.cli.main import main

    text = "write to zq7.marker@example.test from 192.0.2.44."
    s, e = text.index("zq7"), text.index(" from")
    i = text.index("192")
    rows = {
        "uid": ["uid-marker-1"],
        "text": [text],
        "spans": [
            f"[{{'start': {s}, 'end': {e}, 'label': 'email'}},"
            f" {{'start': {i}, 'end': {i + 10}, 'label': 'ipv4'}}]"
        ],
        "locale": ["us"],
        "document_format": ["unstructured"],
    }
    src = tmp_path / "src.parquet"
    pq.write_table(pa.table(rows), src)
    data = src.read_bytes()
    ds = replace(
        NEMOTRON_PII, splits={"test": DataFile("data/t.parquet", hashlib.sha256(data).hexdigest(), len(data))}
    )
    monkeypatch.setitem(datasets.DATASETS, "nemotron-pii", ds)
    dest = datasets.local_path(ds, tmp_path / "data", "test")
    dest.parent.mkdir(parents=True)
    dest.write_bytes(data)
    out = tmp_path / "report.json"

    assert (
        main(["evaluate", "run", "nemotron-pii", "--data-dir", str(tmp_path / "data"), "--json", str(out)])
        == 0
    )
    report = json.loads(out.read_text())
    assert report["by_type"]["EMAIL"]["recall_strict"] == 1.0
    assert report["by_type"]["IPV4"]["recall_strict"] == 1.0  # ends the sentence
    assert report["dataset"]["file_sha256"] == hashlib.sha256(data).hexdigest()
    printed = capsys.readouterr().out + out.read_text()
    for fragment in ("zq7", "marker", "192.0.2.44", "write to"):
        assert fragment not in printed


def _pinned_standin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    pa = pytest.importorskip("pyarrow")
    pq = pytest.importorskip("pyarrow.parquet")
    rows = {
        "uid": ["a", "b"],
        "text": ["mail x@y.test", "mail z@y.test"],
        "spans": [
            "[{'start': 5, 'end': 13, 'label': 'email'}]",
            "[{'start': 5, 'end': 13, 'label': 'email'}]",
        ],
        "locale": ["us", "us"],
        "document_format": ["unstructured"] * 2,
    }
    src = tmp_path / "src.parquet"
    pq.write_table(pa.table(rows), src)
    data = src.read_bytes()
    ds = replace(
        NEMOTRON_PII, splits={"test": DataFile("data/t.parquet", hashlib.sha256(data).hexdigest(), len(data))}
    )
    monkeypatch.setitem(datasets.DATASETS, "nemotron-pii", ds)
    dest = datasets.local_path(ds, tmp_path / "data", "test")
    dest.parent.mkdir(parents=True)
    dest.write_bytes(data)
    return tmp_path / "data"


def test_cli_min_score_writes_one_report_per_threshold(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import json

    from prompt_privacy.cli.main import main
    from prompt_privacy.evaluation import systems
    from prompt_privacy.evaluation.scoring import System

    data_dir = _pinned_standin(tmp_path, monkeypatch)

    def scored(texts: list[str]) -> list[list[Span]]:  # first doc confident, second not
        return [[Span(5, 13, "EMAIL", 0.9)], [Span(5, 13, "EMAIL", 0.2)]][: len(texts)]

    monkeypatch.setattr(
        systems, "ppe_rules", lambda phone_context=False: System("fake", frozenset({"EMAIL"}), scored)
    )
    out = tmp_path / "r.json"
    rc = main(
        [
            "evaluate",
            "run",
            "nemotron-pii",
            "--data-dir",
            str(data_dir),
            "--min-score",
            "0,0.5",
            "--json",
            str(out),
        ]
    )
    assert rc == 0
    low = json.loads((tmp_path / "r-min0.json").read_text())
    high = json.loads((tmp_path / "r-min0.5.json").read_text())
    assert (low["by_type"]["EMAIL"]["found_overlap"], high["by_type"]["EMAIL"]["found_overlap"]) == (2, 1)
    assert (low["system"]["min_score"], high["system"]["min_score"]) == (0.0, 0.5)


def test_cli_presidio_needs_a_model_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from prompt_privacy.cli.main import main

    data_dir = _pinned_standin(tmp_path, monkeypatch)
    assert main(["evaluate", "run", "nemotron-pii", "--data-dir", str(data_dir), "--system", "presidio"]) == 2


def test_out_of_range_spans_are_dropped_and_counted_only_where_declared() -> None:
    raw = '[{"start": 0, "end": 4, "label": "name"}, {"start": 2, "end": 99, "label": "name"}]'
    gretel = datasets.GRETEL_PII_FINANCE
    row = {"index": 7, "generated_text": "Anna Berg", "pii_spans": raw, "language": "Swedish"}
    d = row_doc(gretel, row)
    assert d.gold == (Span(0, 4, "name"),) and d.dropped == ("name",) and d.tags == (("language", "Swedish"),)
    with pytest.raises(ValueError, match="outside a text"):
        row_doc(replace(gretel, out_of_range="reject"), row)
    with pytest.raises(ValueError, match="out_of_range"):
        row_doc(replace(gretel, out_of_range="ignore"), row)
    sc = Scorer(gretel.label_map)
    sc.add(d, [])
    r = sc.report()
    assert r["gold_dropped_out_of_range"] == {"name": 1} and r["by_label"]["name"]["support"] == 1
    assert "gold spans dropped (outside their text, not scored): {'name': 1}" in table(r)
    clean = Scorer(gretel.label_map)
    clean.add(row_doc(gretel, {**row, "pii_spans": "[]"}), [])
    assert "gold_dropped_out_of_range" not in clean.report()


def test_json_spans_are_parsed_as_json_only() -> None:
    assert parse_spans('[{"start": 0, "end": 2, "label": "x"}]', 5, "json") == (Span(0, 2, "x"),)
    with pytest.raises(ValueError):
        parse_spans("[{'start': 0, 'end': 2, 'label': 'x'}]", 5, "json")  # a Python literal is not JSON
    with pytest.raises(ValueError, match="unknown syntax"):
        parse_spans("[]", 5, "yaml")

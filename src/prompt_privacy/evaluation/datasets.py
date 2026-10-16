"""Pinned public datasets: where they come from, how they are checked, how they are read.

A dataset is fetched once into a directory outside the repository (`ppe evaluate fetch`). The
download is pinned to a revision and every file is checked against its published size and SHA-256
before it is kept; `run` checks the hash again, so a result always names the exact bytes it scored.
Only data is downloaded; nothing from a dataset repository is executed.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import urllib.request
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from prompt_privacy.evaluation.scoring import Doc, Span

_CHUNK = 1 << 20


@dataclass(frozen=True)
class DataFile:
    path: str  # relative to the dataset repository and to the local data directory
    sha256: str
    size: int


@dataclass(frozen=True)
class Dataset:
    name: str
    repo: str  # Hugging Face dataset repository
    revision: str  # commit; never a branch name
    licence: str
    attribution: str
    splits: Mapping[str, DataFile]
    label_map: Mapping[str, str]  # dataset label -> canonical type, only where every span is that type
    compatible: Mapping[str, frozenset[str]] = field(default_factory=dict)
    slice_keys: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    columns: Mapping[str, str] = field(  # role -> column name in the parquet file
        default_factory=lambda: {"uid": "uid", "text": "text", "spans": "spans"}
    )
    span_syntax: str = "python"  # how the spans column is written: "python" literal or "json"
    # A gold span outside its text: "reject" the dataset (an error), or "drop" the span and count it in
    # the report. Only for a dataset whose card or profile shows such spans; the default is strict.
    out_of_range: str = "reject"

    def url(self, f: DataFile) -> str:
        return f"https://huggingface.co/datasets/{self.repo}/resolve/{self.revision}/{f.path}"


NEMOTRON_PII = Dataset(
    name="nemotron-pii",
    repo="nvidia/Nemotron-PII",
    revision="b70ffaf5ff39e079776134c5bf4381f00a9fd1ed",
    licence="CC-BY-4.0",
    attribution=(
        "Nemotron-PII: Synthesized Data for Privacy-Preserving AI. Steier, Manoel, Haushalter, "
        "Van Segbroeck; NVIDIA, 2025. https://huggingface.co/datasets/nvidia/Nemotron-PII "
        "(CC BY 4.0). Only aggregate counts derived from it are published here; no records."
    ),
    splits={
        "test": DataFile(
            "data/test-00000-of-00001.parquet",
            "1a4b0512ecb5370f0992d29d0f9c07351e6de13f0d7ea33bb18cecb984780247",
            150968398,
        ),
    },
    # Only labels whose every span is of one canonical type, chosen from the label's meaning before any
    # system was scored (2026-10-16) and the same for every system. Labels left out (account_number,
    # customer_id, postcode, ...) are still scored for any-type coverage.
    label_map={
        "email": "EMAIL",
        "phone_number": "PHONE",
        "fax_number": "PHONE",
        "credit_debit_card": "CARD",
        "ipv4": "IPV4",
        "ipv6": "IPV6",
        "api_key": "SECRET",
        "password": "SECRET",
        "first_name": "PERSON",
        "last_name": "PERSON",
        "city": "LOCATION",
        "county": "LOCATION",
        "state": "LOCATION",
        "country": "LOCATION",
        "street_address": "LOCATION",
        "date": "DATE_TIME",
        "date_time": "DATE_TIME",
        "date_of_birth": "DATE_TIME",
        "time": "DATE_TIME",
        "url": "URL",
        "ssn": "US_SSN",
        "company_name": "ORGANIZATION",
        "age": "AGE",
        "mac_address": "MAC_ADDRESS",
    },
    # Labels that may hold the type among other things: a finding on them is not a false positive,
    # but they are not counted as support for the type.
    compatible={
        "IBAN": frozenset({"account_number"}),
        "NRIC": frozenset({"national_id"}),
        "SECRET": frozenset({"http_cookie"}),
    },
    slice_keys=("locale", "document_format"),
    notes=(
        "The test split holds 100,000 rows: 50,000 uids, each once with locale=us and once with "
        "locale=intl (different texts). The card's '50k test' counts uids.",
        "Span offsets are authoritative: every span's text equals the text at its offsets except for "
        "letter case (6,195) or an integer-typed value (6,747); the scorer uses offsets only.",
        "No Singapore NRIC/FIN or IBAN label exists; those PPE types are scored for precision only.",
        "A name is labelled as first_name and last_name separately; a system span over the full name "
        "overlaps both (found for overlap recall), but matches neither exactly (strict recall).",
    ),
)

GRETEL_PII_FINANCE = Dataset(
    name="gretel-pii-finance",
    repo="gretelai/synthetic_pii_finance_multilingual",
    revision="7b844d16738527a04264f50214cb426a4cea0897",
    licence="Apache-2.0",
    attribution=(
        "Synthetic-PII-Financial-Documents-North-America: A synthetic dataset for training language "
        "models to label and detect PII in domain specific formats. Watson, Meyer, Van Segbroeck, "
        "Grossman, Torbey, Mlocek, Greco; Gretel, 2024. "
        "https://huggingface.co/datasets/gretelai/synthetic_pii_finance_multilingual (Apache 2.0). "
        "Only aggregate counts derived from it are published here; no records."
    ),
    splits={
        "test": DataFile(
            "data/test-00000-of-00001.parquet",
            "014e1057978f030fce4f4cad7c93b9e3377fd0ded713d2bf4c7de00e3e3c8c72",
            5422540,
        ),
    },
    # Chosen from the labels' meaning before any system was scored on this dataset (2026-10-16), with
    # the same choices as for Nemotron where the labels agree. `ssn` is left out: tag names follow
    # Python Faker, whose ssn() is locale-specific (a Swedish personnummer, a Dutch BSN, ...), so it is
    # not one type across the seven languages.
    label_map={
        "email": "EMAIL",
        "phone_number": "PHONE",
        "credit_card_number": "CARD",
        "iban": "IBAN",
        "ipv4": "IPV4",
        "ipv6": "IPV6",
        "api_key": "SECRET",
        "password": "SECRET",
        "name": "PERSON",
        "first_name": "PERSON",
        "last_name": "PERSON",
        "street_address": "LOCATION",
        "date": "DATE_TIME",
        "date_of_birth": "DATE_TIME",
        "date_time": "DATE_TIME",
        "time": "DATE_TIME",
        "company": "ORGANIZATION",
    },
    slice_keys=("language",),
    columns={"uid": "index", "text": "generated_text", "spans": "pii_spans"},
    span_syntax="json",
    out_of_range="drop",
    notes=(
        "27 gold spans in 8 documents end past the end of their text (19 of them `name`); they are "
        "dropped and counted in the report (gold_dropped_out_of_range).",
        "409 pairs of gold spans overlap (mostly name/name and company/company, nested or crossing); "
        "each gold span is scored on its own.",
        "Gold spans were labelled with the help of an NER library (GLiNER), filtered by an LLM judge "
        "and spot-checked by people; the card warns that missed and wrong labels remain.",
        "Seven languages (English, Spanish, Swedish, German, Italian, Dutch, French); slices by language.",
    ),
)

DATASETS: dict[str, Dataset] = {d.name: d for d in (NEMOTRON_PII, GRETEL_PII_FINANCE)}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(_CHUNK):
            h.update(chunk)
    return h.hexdigest()


def fetch_file(url: str, dest: Path, sha256: str, size: int) -> None:
    """Download `url` to `dest` only if it has exactly `size` bytes and hash `sha256`.

    Written to a temporary name and renamed on success; on any mismatch nothing is left behind.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".part")
    h = hashlib.sha256()
    n = 0
    try:
        with urllib.request.urlopen(url, timeout=60) as resp, tmp.open("wb") as out:  # noqa: S310 — scheme checked by callers
            while chunk := resp.read(_CHUNK):
                n += len(chunk)
                if n > size:
                    raise ValueError(f"{dest.name}: more than the expected {size} bytes")
                h.update(chunk)
                out.write(chunk)
        if n != size or h.hexdigest() != sha256:
            raise ValueError(f"{dest.name}: got {n} bytes, sha256 {h.hexdigest()}; expected {size}, {sha256}")
        os.replace(tmp, dest)
    finally:
        tmp.unlink(missing_ok=True)


def fetch(ds: Dataset, data_dir: Path, split: str) -> Path:
    f = ds.splits[split]
    dest = local_path(ds, data_dir, split)
    if dest.exists() and sha256_file(dest) == f.sha256:
        return dest
    url = ds.url(f)
    if not url.startswith("https://"):
        raise ValueError("datasets are fetched over https only")
    fetch_file(url, dest, f.sha256, f.size)
    return dest


def local_path(ds: Dataset, data_dir: Path, split: str) -> Path:
    return data_dir / ds.repo.replace("/", "-") / ds.splits[split].path


def verify(ds: Dataset, data_dir: Path, split: str) -> Path:
    path = local_path(ds, data_dir, split)
    if not path.exists():
        raise FileNotFoundError(f"{path} missing: run `ppe evaluate fetch {ds.name} --data-dir {data_dir}`")
    got = sha256_file(path)
    if got != ds.splits[split].sha256:
        raise ValueError(f"{path}: sha256 {got} is not the pinned {ds.splits[split].sha256}")
    return path


def parse_spans(
    raw: str, text_len: int, syntax: str = "python", dropped: list[str] | None = None
) -> tuple[Span, ...]:
    """Nemotron stores spans as a Python literal (single quotes), so `ast.literal_eval`, which only
    builds literals and never runs code; Gretel stores JSON. Every span must lie inside the text: one
    that does not is an error, or, when `dropped` is given, left out with its label appended there."""
    if syntax == "python":
        value = ast.literal_eval(raw)
    elif syntax == "json":
        value = json.loads(raw)
    else:
        raise ValueError(f"spans: unknown syntax {syntax!r}")
    if not isinstance(value, list):
        raise ValueError("spans: expected a list")
    out = []
    for s in value:
        start, end, label = s["start"], s["end"], s["label"]
        if not (isinstance(start, int) and isinstance(end, int) and isinstance(label, str)):
            raise ValueError("spans: start/end must be int and label str")
        if not 0 <= start < end <= text_len:
            if dropped is None:
                raise ValueError(f"spans: [{start}, {end}) outside a text of {text_len} characters")
            dropped.append(label)
            continue
        out.append(Span(start, end, label))
    return tuple(out)


def row_doc(ds: Dataset, row: Mapping[str, Any]) -> Doc:
    c = ds.columns
    text = row[c["text"]]
    if not isinstance(text, str):
        raise ValueError("text: expected a string")
    if ds.out_of_range not in ("reject", "drop"):
        raise ValueError(f"{ds.name}: out_of_range must be 'reject' or 'drop'")
    dropped: list[str] | None = [] if ds.out_of_range == "drop" else None
    gold = parse_spans(row[c["spans"]], len(text), ds.span_syntax, dropped)
    return Doc(
        uid=str(row[c["uid"]]),
        text=text,
        gold=gold,
        tags=tuple((k, str(row[k])) for k in ds.slice_keys),
        dropped=tuple(dropped or ()),
    )


def load(ds: Dataset, path: Path, limit: int | None = None) -> Iterator[Doc]:
    try:
        import pyarrow.parquet as pq  # type: ignore[import-untyped]
    except ImportError as e:  # pragma: no cover - depends on the environment
        raise SystemExit('pyarrow is needed to read parquet: pip install -e ".[bench]"') from e
    columns = [ds.columns["uid"], ds.columns["text"], ds.columns["spans"], *ds.slice_keys]
    pf = pq.ParquetFile(path)
    n = 0
    for batch in pf.iter_batches(batch_size=2048, columns=columns):
        for row in batch.to_pylist():
            if limit is not None and n >= limit:
                return
            n += 1
            yield row_doc(ds, row)

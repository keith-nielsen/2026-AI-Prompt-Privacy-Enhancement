"""Pinned public datasets: where they come from, how they are checked, how they are read.

A dataset is fetched once into a directory outside the repository (`ppe evaluate fetch`). The
download is pinned to a revision and every file is checked against its published size and SHA-256
before it is kept; `run` checks the hash again, so a result always names the exact bytes it scored.
Only data is downloaded; nothing from a dataset repository is executed.
"""

from __future__ import annotations

import ast
import hashlib
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
    # Only labels whose every span is one of PPE's types. Labels left out are still scored for
    # any-type coverage (e.g. ssn, account_number): PPE does not claim them, and the report shows that.
    label_map={
        "email": "EMAIL",
        "phone_number": "PHONE",
        "fax_number": "PHONE",
        "credit_debit_card": "CARD",
        "ipv4": "IPV4",
        "ipv6": "IPV6",
        "api_key": "SECRET",
        "password": "SECRET",
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
    ),
)

DATASETS: dict[str, Dataset] = {d.name: d for d in (NEMOTRON_PII,)}


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


def parse_spans(raw: str, text_len: int) -> tuple[Span, ...]:
    """Nemotron stores spans as a Python literal (single quotes), so `ast.literal_eval`, which only
    builds literals and never runs code. Every span must lie inside the text."""
    value = ast.literal_eval(raw)
    if not isinstance(value, list):
        raise ValueError("spans: expected a list")
    out = []
    for s in value:
        start, end, label = s["start"], s["end"], s["label"]
        if not (isinstance(start, int) and isinstance(end, int) and isinstance(label, str)):
            raise ValueError("spans: start/end must be int and label str")
        if not 0 <= start < end <= text_len:
            raise ValueError(f"spans: [{start}, {end}) outside a text of {text_len} characters")
        out.append(Span(start, end, label))
    return tuple(out)


def nemotron_doc(row: Mapping[str, Any], slice_keys: tuple[str, ...]) -> Doc:
    text = row["text"]
    return Doc(
        uid=str(row["uid"]),
        text=text,
        gold=parse_spans(row["spans"], len(text)),
        tags=tuple((k, str(row[k])) for k in slice_keys),
    )


def load(ds: Dataset, path: Path, limit: int | None = None) -> Iterator[Doc]:
    try:
        import pyarrow.parquet as pq  # type: ignore[import-untyped]
    except ImportError as e:  # pragma: no cover - depends on the environment
        raise SystemExit('pyarrow is needed to read parquet: pip install -e ".[bench]"') from e
    columns = ["uid", "text", "spans", *ds.slice_keys]
    pf = pq.ParquetFile(path)
    n = 0
    for batch in pf.iter_batches(batch_size=2048, columns=columns):
        for row in batch.to_pylist():
            if limit is not None and n >= limit:
                return
            n += 1
            yield nemotron_doc(row, ds.slice_keys)

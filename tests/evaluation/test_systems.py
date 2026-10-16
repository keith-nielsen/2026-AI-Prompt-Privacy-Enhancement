"""Systems under test: the PPE wrapper and Presidio's entity mapping (no Presidio or model needed)."""

import importlib
from dataclasses import dataclass
from pathlib import Path

import pytest

from prompt_privacy.evaluation.scoring import CANONICAL_TYPES, Span
from prompt_privacy.evaluation.systems import PRESIDIO_TYPES, ppe_rules, presidio, presidio_spans


@dataclass
class FakeResult:  # the four fields of presidio_analyzer.RecognizerResult that are read
    entity_type: str
    start: int
    end: int
    score: float


def test_presidio_mapping_targets_are_canonical() -> None:
    assert set(PRESIDIO_TYPES.values()) <= CANONICAL_TYPES


def test_presidio_spans_maps_splits_and_passes_through() -> None:
    text = "ip 192.0.2.1 and 2001:db8::1, licence D1234567, mail a@b.test"
    results = [
        FakeResult("IP_ADDRESS", 3, 12, 0.95),
        FakeResult("IP_ADDRESS", 17, 28, 0.95),
        FakeResult("US_DRIVER_LICENSE", 38, 46, 0.3),
        FakeResult("EMAIL_ADDRESS", 53, 61, 1.0),
    ]
    assert presidio_spans(text, results) == [
        Span(3, 12, "IPV4", 0.95),
        Span(17, 28, "IPV6", 0.95),
        Span(38, 46, "US_DRIVER_LICENSE", 0.3),  # no canonical type: kept under its own name
        Span(53, 61, "EMAIL", 1.0),
    ]


def test_presidio_refuses_a_model_name_or_missing_directory(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not a spaCy model directory"):
        presidio(Path("en_core_web_lg"))  # a name would make Presidio download it
    with pytest.raises(ValueError, match="not a spaCy model directory"):
        presidio(tmp_path)  # a directory without meta.json


def test_ppe_rules_system() -> None:
    s = ppe_rules()
    assert s.name == "ppe-rules" and "PERSON" not in s.claimed and {"EMAIL", "SECRET", "NRIC"} <= s.claimed
    assert s.run(["mail a@b.test", "none"]) == [[Span(5, 13, "EMAIL")], []]
    assert ppe_rules(phone_context=True).config["phone_context"] == "required"


def test_presidio_end_to_end() -> None:
    """Real Presidio on a synthetic sentence. Runs only where Presidio is installed and a local spaCy
    model directory is named in PPE_PRESIDIO_MODEL (bench/harness/pvenv); a model run, so capped."""
    import os

    model = os.environ.get("PPE_PRESIDIO_MODEL")
    if not model:
        pytest.skip("PPE_PRESIDIO_MODEL not set")
    pytest.importorskip("presidio_analyzer")
    s = presidio(Path(model))
    # Presidio validates an email's domain against the Public Suffix List, so a reserved TLD such as
    # .test is not an email to it; example.com is reserved for documentation and on the list.
    text = "Write to jane.tan@example.com or call (415) 555-0123 from 192.0.2.10."
    spans = s.run([text])[0]
    found = {(sp.label, text[sp.start : sp.end]) for sp in spans}
    assert ("EMAIL", "jane.tan@example.com") in found and ("IPV4", "192.0.2.10") in found
    tx = importlib.import_module("tldextract.tldextract")
    assert tx.TLD_EXTRACTOR.suffix_list_urls == () and tx.TLD_EXTRACTOR._cache.enabled is False
    assert {"EMAIL", "PHONE", "CARD", "PERSON", "LOCATION"} <= s.claimed and "NRIC" not in s.claimed
    assert s.config["model"].endswith("-3.8.0") and "SpacyRecognizer" in s.config["recognizers"]

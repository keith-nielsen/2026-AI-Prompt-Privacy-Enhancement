"""Systems under test. Each returns spans labelled with canonical types (`scoring.CANONICAL_TYPES`).

Every system is scored by the same `Scorer` with the same dataset label map; a system only translates
its own entity names here. Types without a canonical equivalent pass through under the system's own
name: they count for any-type coverage and the confusion table, never for typed recall.
"""

from __future__ import annotations

import importlib
import json
from collections.abc import Iterable, Mapping, Sequence
from importlib import metadata
from pathlib import Path
from typing import Any, Protocol

from prompt_privacy import __version__
from prompt_privacy.core.types import EntityType
from prompt_privacy.detectors.base import detect
from prompt_privacy.evaluation.scoring import Span, System


def ppe_rules(phone_context: bool = False) -> System:
    """PPE Stage 0 + Stage 1 (deterministic rules), as `ppe scan` runs them with an empty dictionary."""

    def run(texts: Sequence[str]) -> list[list[Span]]:
        return [
            [Span(f.start, f.end, f.type.value) for f in detect(t, phone_context=phone_context)]
            for t in texts
        ]

    claimed = frozenset(t.value for t in EntityType) - {EntityType.PERSON.value, EntityType.TERM.value}
    return System(
        "ppe-rules",
        claimed,
        run,
        {"ppe": __version__, "phone_context": "required" if phone_context else "optional"},
    )


# Presidio entity -> canonical type. Fixed before Presidio was first scored (2026-10-16).
PRESIDIO_TYPES: Mapping[str, str] = {
    "EMAIL_ADDRESS": "EMAIL",
    "EMAIL": "EMAIL",
    "PHONE_NUMBER": "PHONE",
    "CREDIT_CARD": "CARD",
    "IBAN_CODE": "IBAN",
    "SG_NRIC_FIN": "NRIC",
    "PERSON": "PERSON",
    "LOCATION": "LOCATION",
    "DATE_TIME": "DATE_TIME",
    "URL": "URL",
    "US_SSN": "US_SSN",
    "ORGANIZATION": "ORGANIZATION",
    "AGE": "AGE",
    "MAC_ADDRESS": "MAC_ADDRESS",
    # IP_ADDRESS is split into IPV4 / IPV6 by its text (`presidio_spans`).
}


class _Result(Protocol):
    entity_type: str
    start: int
    end: int
    score: float


def presidio_spans(text: str, results: Iterable[_Result]) -> list[Span]:
    out = []
    for r in results:
        if r.entity_type == "IP_ADDRESS":
            label = "IPV6" if ":" in text[r.start : r.end] else "IPV4"
        else:
            label = PRESIDIO_TYPES.get(r.entity_type, r.entity_type)
        out.append(Span(r.start, r.end, label, float(r.score)))
    return out


def presidio(model_path: Path, batch_size: int = 32) -> System:
    """Presidio Analyzer with its default recognisers and a spaCy model loaded from a local path.

    The path must exist: Presidio downloads a model it cannot find by name, and models on this host
    are loaded from the designated store only. Presidio is an optional, separately installed
    baseline (`bench/harness/pvenv`), never a PPE dependency.
    """
    if not model_path.is_dir() or not (model_path / "meta.json").is_file():
        raise ValueError(f"{model_path}: not a spaCy model directory (no meta.json)")
    try:  # optional, separately installed: imported by name so PPE's type check does not need it
        pa: Any = importlib.import_module("presidio_analyzer")
        pa_nlp: Any = importlib.import_module("presidio_analyzer.nlp_engine")
    except ImportError as e:  # pragma: no cover - depends on the environment
        raise SystemExit(
            "presidio-analyzer is not installed (see bench/2026-10-16-presidio-baseline.md)"
        ) from e
    # Presidio's email recogniser checks the domain with tldextract, which by default downloads the
    # Public Suffix List on first use and caches it under ~/.cache. Use the list bundled with the
    # installed tldextract instead: no network, and the run is fixed by the recorded version.
    tx: Any = importlib.import_module("tldextract.tldextract")
    tx.TLD_EXTRACTOR = tx.TLDExtract(cache_dir=None, suffix_list_urls=(), fallback_to_snapshot=True)
    meta: dict[str, Any] = json.loads((model_path / "meta.json").read_text())
    nlp = pa_nlp.NlpEngineProvider(
        nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": str(model_path)}],
        }
    ).create_engine()
    analyzer = pa.AnalyzerEngine(nlp_engine=nlp, supported_languages=["en"])
    batch = pa.BatchAnalyzerEngine(analyzer)
    emitted = set(analyzer.get_supported_entities("en"))
    claimed = frozenset(PRESIDIO_TYPES[e] for e in emitted if e in PRESIDIO_TYPES)
    if "IP_ADDRESS" in emitted:
        claimed |= {"IPV4", "IPV6"}

    def run(texts: Sequence[str]) -> list[list[Span]]:
        results = batch.analyze_iterator(list(texts), language="en", batch_size=batch_size)
        return [presidio_spans(t, r) for t, r in zip(texts, results, strict=True)]

    return System(
        "presidio",
        claimed,
        run,
        {
            "presidio_analyzer": metadata.version("presidio-analyzer"),
            "spacy": metadata.version("spacy"),
            "tldextract": metadata.version("tldextract") + " (bundled suffix-list snapshot, offline)",
            "model": f"{meta['lang']}_{meta['name']}-{meta['version']}",
            "recognizers": ",".join(
                sorted(r.name for r in analyzer.registry.get_recognizers("en", all_fields=True))
            ),
            "entities": ",".join(sorted(emitted)),
            "configuration": "defaults (no custom recognisers, no context words added, no allow list)",
        },
    )

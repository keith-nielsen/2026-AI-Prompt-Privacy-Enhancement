"""Conformance: repository-level claims (docs hygiene, versions, data policy, knob catalogue).

See tests/conformance/test_claims_engine.py for the C-nn / F-nn convention.
"""

from __future__ import annotations

import re
import subprocess
import tomllib
from pathlib import Path

import pytest

from prompt_privacy import __version__, knobs, policy
from prompt_privacy.core.checksums import iban_valid, luhn_valid, nric_valid
from prompt_privacy.core.types import EntityType as T
from prompt_privacy.detectors.base import detect

ROOT = Path(__file__).resolve().parents[2]


def _tracked(*patterns: str) -> list[Path]:
    out = subprocess.run(  # noqa: S603 — fixed git command, patterns are literals in this file
        ["git", "ls-files", *patterns],  # noqa: S607 — git from PATH, as in the dev workflow
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return [ROOT / p for p in out.stdout.split()]


def test_c44_docs_contain_no_stray_tool_markup() -> None:
    """C-44 (docs quality; agent safety): no leftover `</invoke>`-style markup in tracked text files."""
    pattern = re.compile(r"</?(?:invoke|parameter)\b|</content>")
    offenders = [p.relative_to(ROOT) for p in _tracked("*.md") if pattern.search(p.read_text())]
    assert offenders == []


def test_c50_docs_free_of_invisible_and_bidi_characters() -> None:
    """C-50 (CONTRIBUTING Trojan Source rule; tests/test_source_hygiene.py does not cover docs)."""
    bad = re.compile("[\u200b-\u200f\u2060\ufeff\u00ad\u202a-\u202e\u2066-\u2069]")
    assert [p.name for p in _tracked("*.md", "*.cff", "*.toml") if bad.search(p.read_text())] == []


def test_c51_version_is_consistent_and_marked_pre_alpha() -> None:
    """C-51 (release v0.1.0.dev1, pre-alpha): pyproject, package, CITATION and README agree."""
    meta = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert meta["version"] == __version__
    assert "Development Status :: 2 - Pre-Alpha" in meta["classifiers"]
    assert f"version: {__version__}" in (ROOT / "CITATION.cff").read_text()
    readme = (ROOT / "README.md").read_text()
    assert "pre-alpha" in readme.lower() and __version__ in readme


@pytest.mark.xfail(
    strict=True, reason="F-14: bench/results commits corpus-generated checksum-valid identifiers"
)
def test_c46_no_generated_checksum_valid_identifiers_committed() -> None:
    """C-46 (corpus/generator.py: generated values 'can coincide with a real one by chance, so the corpus is
    generated at test time and not committed'). Published sample values used in docs/tests are allowed."""
    allowed = {"S1234567D", "T9119134I", "M1235467X", "4111111111111111", "GB82WEST12345698765432"}
    found: list[str] = []
    for p in _tracked("bench/*"):
        if p.suffix in (".txt", ".json", ".jsonl", ".log", ".md"):
            for f in detect(p.read_text(errors="replace")):
                v = re.sub(r"[\s-]", "", f.value).upper()
                valid = (
                    (f.type is T.NRIC and nric_valid(v))
                    or (f.type is T.CARD and luhn_valid(v))
                    or (f.type is T.IBAN and iban_valid(v))
                )
                if valid and v not in allowed:
                    found.append(f"{p.relative_to(ROOT)}:{f.type.value}")
    assert found == []


@pytest.mark.xfail(
    strict=True, reason="F-20: SECURITY.md/CONTRIBUTING.md still say 'design phase, no executable code'"
)
def test_c47_security_and_contributing_describe_the_current_state() -> None:
    """C-47 (SECURITY.md 'Status'): the policy describes what is actually shipped (v0.1.0.dev1 has code)."""
    for name in ("SECURITY.md", "CONTRIBUTING.md"):
        text = (ROOT / name).read_text().lower()
        assert "no executable code" not in text and "design phase" not in text, name


@pytest.mark.xfail(strict=True, reason="F-20: README 'Read' table lists ADR-0001 … ADR-0012; ADR-0013 exists")
def test_c48_readme_adr_index_is_current() -> None:
    """C-48 (README 'Read' table)."""
    adrs = sorted(p.name[:8] for p in (ROOT / "docs/design").glob("ADR-*.md"))
    assert f"ADR-0001 … {adrs[-1]}" in (ROOT / "README.md").read_text()


@pytest.mark.xfail(
    strict=True, reason="F-20: detection.dictionary is configurable but has no knob/trade-off entry"
)
def test_c49_every_policy_setting_has_a_knob_with_trade_off_and_test() -> None:
    """C-49 (knobs.py: 'every setting with its trade-off and the test that proves it'; ADR-0012 §3)."""
    leaves: list[str] = []

    def walk(node: dict, prefix: str = "") -> None:  # type: ignore[type-arg]
        for k, v in (node.get("properties") or {}).items():
            if v.get("type") == "object" and "properties" in v:
                walk(v, f"{prefix}{k}.")
            else:
                leaves.append(f"{prefix}{k}")

    walk(policy.schema("policy"))
    paths = {k.path for k in knobs.KNOBS}
    assert [leaf for leaf in leaves if leaf != "profile" and leaf not in paths] == []
    assert [k.path for k in knobs.KNOBS if k.implemented and k.path not in leaves] == []

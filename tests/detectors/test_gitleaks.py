"""Imported Gitleaks rules: the pinned rule file, and matching as Gitleaks v8.30.1 does it.

Rule behaviour is tested on small rule files written here (`_rules`), so each semantic (keyword
prefilter, secret group, entropy, allow-lists, generic dedupe) is checked on its own. Fake secret
values are assembled at run time so the source holds no complete token.
"""

from __future__ import annotations

import hashlib
import time
from importlib import resources

import pytest

from prompt_privacy.core.types import EntityType as T
from prompt_privacy.detectors import gitleaks
from prompt_privacy.detectors.base import detect

_RANDOM = "Zq8vT2mX" + "9pL4wR7n" + "K3bY"  # 20 characters, entropy above 3.5, has digits


def _rules(toml: str) -> gitleaks.RuleSet:
    raw = toml.encode()
    return gitleaks.parse(raw, hashlib.sha256(raw).hexdigest())


def test_rule_file_is_the_pinned_gitleaks_release() -> None:
    files = resources.files("prompt_privacy.detectors").joinpath("gitleaks_rules")
    raw = files.joinpath(gitleaks.RULES_FILE).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == gitleaks.RULES_SHA256
    assert gitleaks.GITLEAKS_VERSION == "8.30.1"
    licence = files.joinpath("LICENSE").read_text()
    assert licence.startswith("MIT License") and "Zachary Rice" in licence
    rs = gitleaks.rule_set()
    assert len(rs.rules) == 217
    assert rs.skipped == (
        "freemius-secret-key",
        "hashicorp-tf-password",
        "kubernetes-secret-yaml",
        "nuget-config-password",
        "pkcs12-file",
    )


def test_parse_refuses_a_changed_rule_file_or_unknown_keys() -> None:
    raw = resources.files("prompt_privacy.detectors").joinpath("gitleaks_rules", gitleaks.RULES_FILE)
    with pytest.raises(ValueError, match="SHA-256"):
        gitleaks.parse(raw.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="not supported"):
        _rules('[[rules]]\nid = "x"\nregex = "a"\nrequired = []\n')
    with pytest.raises(ValueError, match="not supported"):
        _rules('[[rules]]\nid = "x"\nregex = "a"\n[[rules.allowlists]]\ntargetRules = ["y"]\n')
    with pytest.raises(ValueError, match="not supported"):
        _rules('extend = {}\n[[rules]]\nid = "x"\nregex = "a"\n')


@pytest.mark.parametrize(("s", "bits"), [("", 0.0), ("aaaa", 0.0), ("ab", 1.0), ("abcd", 2.0), ("é", 0.5)])
def test_shannon_entropy_as_gitleaks(s: str, bits: float) -> None:
    # Gitleaks counts characters but divides by the UTF-8 length ("é" is two bytes).
    assert gitleaks.shannon_entropy(s) == pytest.approx(bits)


def test_keyword_prefilter() -> None:
    rs = _rules('[[rules]]\nid = "t"\nregex = "tok_[0-9]{4}"\nkeywords = ["ZZ"]\n')
    assert gitleaks.find("tok_1234", rs) == []
    assert gitleaks.find("zz tok_1234", rs) == [(3, 11, "t")]


def test_secret_is_the_group_or_first_non_empty_group() -> None:
    rs = _rules(
        '[[rules]]\nid = "first"\nregex = "(x)?k=(v[0-9]+)"\n'
        '[[rules]]\nid = "group2"\nregex = "(a)(b[0-9])"\nsecretGroup = 2\n'
        '[[rules]]\nid = "whole"\nregex = "\\n?w[0-9]+\\n?"\n'
    )
    assert gitleaks.find("k=v12", rs) == [(2, 5, "first")]
    assert gitleaks.find("xk=v12", rs) == [(0, 1, "first")]  # both groups match: the first one wins
    assert gitleaks.find("ab7", rs) == [(1, 3, "group2")]
    assert gitleaks.find("\nw42\n", rs) == [(1, 4, "whole")]  # line breaks trimmed from the match


def test_entropy_must_be_above_the_threshold() -> None:
    rs = _rules('[[rules]]\nid = "e"\nregex = "s=([a-d]+)"\nentropy = 2.0\n')
    assert gitleaks.find("s=abcd", rs) == []  # exactly 2.0: dropped, as Gitleaks (`<=`)
    assert gitleaks.find("s=abcda", rs) == []
    rs = _rules('[[rules]]\nid = "e"\nregex = "s=([a-z]+)"\nentropy = 2.0\n')
    assert gitleaks.find("s=abcde", rs) == [(2, 7, "e")]


def test_allowlists() -> None:
    base = '[[rules]]\nid = "r"\nregex = "k=([a-z0-9]+)"\n'
    stop = _rules(base + '[[rules.allowlists]]\nregexTarget = "match"\nstopwords = ["demo", "k="]\n')
    assert gitleaks.find("k=demo12", stop) == []  # stop words are checked on the secret, not the match
    assert gitleaks.find("k=real12", stop) == [(2, 8, "r")]
    line = _rules(base + '[[rules.allowlists]]\nregexTarget = "line"\nregexes = ["^#"]\n')
    assert gitleaks.find("# k=abc1", line) == []
    assert gitleaks.find("x k=abc1", line) == [(4, 8, "r")]
    both = _rules(base + '[[rules.allowlists]]\ncondition = "AND"\nregexes = ["1$"]\nstopwords = ["ab"]\n')
    assert gitleaks.find("k=ab1", both) == []
    assert gitleaks.find("k=ab2", both) == [(2, 5, "r")]
    # A check that needs a file path never passes: a prompt has none.
    path = _rules(base + '[[rules.allowlists]]\ncondition = "AND"\npaths = [".*"]\nregexes = [".*"]\n')
    assert gitleaks.find("k=abc1", path) == [(2, 6, "r")]
    glob = _rules('[allowlist]\nstopwords = ["demo"]\n' + base)
    assert gitleaks.find("k=demo1", glob) == []


def test_rules_that_need_a_file_path_are_skipped() -> None:
    rs = _rules('[[rules]]\nid = "p"\nregex = "a"\npath = "\\\\.tf$"\n[[rules]]\nid = "f"\npath = "x"\n')
    assert rs.rules == () and rs.skipped == ("p", "f")


def test_generic_finding_gives_way_to_a_specific_rule() -> None:
    rs = _rules(
        '[[rules]]\nid = "generic-x"\nregex = "key=([a-z0-9_]+)"\n'
        '[[rules]]\nid = "vendor"\nregex = "(v_[a-z0-9_]+)"\n'
    )
    assert gitleaks.find("key=v_ab12", rs) == [(4, 10, "vendor")]
    assert gitleaks.find("key=ab12 v_cd34", rs) == [(4, 8, "generic-x"), (9, 15, "vendor")]


def test_generic_api_key_in_detect() -> None:
    text = f'é config: api_key = "{_RANDOM}"\n'
    fs = [f for f in detect(text) if f.type is T.SECRET]
    assert [(f.value, f.subtype, f.detector) for f in fs] == [
        (_RANDOM, "gitleaks:generic-api-key", "rules.gitleaks")
    ]
    assert text[fs[0].start : fs[0].end] == _RANDOM  # character offsets, after a non-ASCII character


@pytest.mark.parametrize(
    "value",
    [
        "a" * 20,  # entropy too low
        "Example" + _RANDOM,  # a stop word
        "abcdefghijKLMNOPQRST",  # letters only: allow-listed
    ],
)
def test_generic_api_key_drops_placeholders(value: str) -> None:
    assert gitleaks.find(f'api_key = "{value}"\n') == []


def test_vendor_rule_in_detect() -> None:
    token = "glpat-" + "Xy7_" + "kP2m" + "Qw9z" + "Ln4v" + "Rt8b"
    fs = [f for f in detect(f"token {token} end") if f.type is T.SECRET]
    assert [(f.value, f.subtype) for f in fs] == [(token, "gitleaks:gitlab-pat")]


def test_every_keyword_with_long_input_stays_fast() -> None:
    """RE2 keeps matching linear: every rule runs (all keywords present) on 200,000 characters."""
    rs = gitleaks.rule_set()
    keywords = " ".join(sorted({k for r in rs.rules for k in r.keywords}))
    text = keywords + " = " + ("aB3+/" * 40_000)
    t0 = time.perf_counter()
    gitleaks.find(text)
    assert time.perf_counter() - t0 < 5.0


def test_assignment_placeholders_are_dropped_by_gitleaks_words() -> None:
    text = "export API_KEY=changeme123\nexport API_KEY=abcd1234efgh5678\n"
    fs = [(f.subtype, f.value) for f in detect(text) if f.type is T.SECRET]
    assert fs == [("assignment", "abcd1234efgh5678")]
    assert len(gitleaks.stopwords()) == 1448 and gitleaks.has_stopword("ChangeMe")

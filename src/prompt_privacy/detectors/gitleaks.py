"""Stage 1 secret rules imported from Gitleaks (MIT; `gitleaks_rules/LICENSE`), applied as Gitleaks does.

The rule file is Gitleaks' default config, vendored unchanged and pinned by SHA-256. Its regexes are
Go (RE2) syntax and run on RE2 (`google-re2`): the same semantics as Gitleaks, and linear time on any
input. Matching follows Gitleaks v8.30.1 `detect/detect.go` (`detectRule`):

- a rule runs only if one of its keywords occurs in the lower-cased text;
- the secret is the rule's `secretGroup`, else the first non-empty capture group, else the match
  (with surrounding line breaks trimmed);
- a rule with `entropy` keeps a secret only if its Shannon entropy is above it;
- the global allow-list, then the rule's allow-lists, drop a finding (regexes on the secret, the
  match or the line; stop words in the secret; "AND" requires every check that applies).

Differences, all because a prompt is not a file in a repository: there is no file path, so rules
and allow-list checks that need one never apply (as in Gitleaks with an empty path); there is no
commit; text is not decoded (base64, hex, percent) before matching; and a `gitleaks:allow` comment
does not exempt a line (Gitleaks' `--ignore-gitleaks-allow`), since pasted code must not be able to
switch protection off. Any rule-file key not listed here is refused at load, so an updated rule file
cannot silently change meaning.
"""

from __future__ import annotations

import hashlib
import math
import tomllib
from collections import Counter
from dataclasses import dataclass
from functools import cache
from importlib import resources
from typing import Any

import re2  # type: ignore[import-untyped]

GITLEAKS_VERSION = "8.30.1"
RULES_FILE = "gitleaks.toml"  # config/gitleaks.toml at tag v8.30.1
RULES_SHA256 = "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf"

_RULE_KEYS = {
    "id",
    "description",
    "regex",
    "entropy",
    "keywords",
    "allowlists",
    "path",
    "secretGroup",
    "tags",
}
_ALLOWLIST_KEYS = {"description", "regexes", "regexTarget", "stopwords", "paths", "condition", "commits"}


@dataclass(frozen=True)
class Allowlist:
    match_all: bool  # condition "AND"
    target: str  # "secret", "match" or "line"
    regex: Any  # one RE2 pattern for all regexes, or None
    stopwords: tuple[str, ...]  # lower-case
    needs_path_or_commit: bool  # has paths or commits: never true for a prompt

    def allows(self, secret: str, match: str, line: str) -> bool:
        target = {"secret": secret, "match": match, "line": line}[self.target]
        regex_ok = self.regex is not None and self.regex.search(target) is not None
        low = secret.lower()
        stop_ok = any(w in low for w in self.stopwords)
        if not self.match_all:
            return regex_ok or stop_ok
        checks = [False] if self.needs_path_or_commit else []
        if self.regex is not None:
            checks.append(regex_ok)
        if self.stopwords:
            checks.append(stop_ok)
        return bool(checks) and all(checks)


@dataclass(frozen=True)
class Rule:
    id: str
    regex: Any  # RE2 pattern
    keywords: tuple[str, ...]  # lower-case; empty = always run
    entropy: float  # 0 = no entropy check
    secret_group: int  # 0 = first non-empty group
    allowlists: tuple[Allowlist, ...]


@dataclass(frozen=True)
class RuleSet:
    rules: tuple[Rule, ...]
    allowlists: tuple[Allowlist, ...]  # global
    skipped: tuple[str, ...]  # rules that need a file path


def shannon_entropy(s: str) -> float:
    """As Gitleaks computes it: counts per character, divided by the UTF-8 length."""
    if not s:
        return 0.0
    n = len(s.encode("utf-8"))
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _allowlist(a: dict[str, Any]) -> Allowlist:
    unknown = set(a) - _ALLOWLIST_KEYS
    if unknown:
        raise ValueError(f"gitleaks allow-list keys not supported: {sorted(unknown)}")
    condition = str(a.get("condition", "")).upper()
    if condition not in ("", "OR", "||", "AND", "&&"):
        raise ValueError(f"gitleaks allow-list condition {condition!r}")
    target = a.get("regexTarget") or "secret"
    if target not in ("secret", "match", "line"):
        raise ValueError(f"gitleaks allow-list regexTarget {target!r}")
    regexes = a.get("regexes", [])
    return Allowlist(
        match_all=condition in ("AND", "&&"),
        target=target,
        regex=re2.compile("|".join(f"(?:{r})" for r in regexes)) if regexes else None,
        stopwords=tuple(w.lower() for w in a.get("stopwords", [])),
        needs_path_or_commit=bool(a.get("paths") or a.get("commits")),
    )


def parse(raw: bytes, sha256: str = RULES_SHA256) -> RuleSet:
    """The rule set in `raw`, which must hash to `sha256` (the pinned rule file by default)."""
    if hashlib.sha256(raw).hexdigest() != sha256:
        raise ValueError(f"{RULES_FILE}: SHA-256 does not match the pinned Gitleaks {GITLEAKS_VERSION} rules")
    cfg = tomllib.loads(raw.decode("utf-8"))
    unknown = set(cfg) - {"title", "minVersion", "allowlist", "allowlists", "rules"}
    if unknown:
        raise ValueError(f"gitleaks config keys not supported: {sorted(unknown)}")
    rules, skipped = [], []
    for r in cfg["rules"]:
        unknown = set(r) - _RULE_KEYS
        if unknown:
            raise ValueError(f"gitleaks rule {r.get('id')}: keys not supported: {sorted(unknown)}")
        # A rule with a path applies only to files whose path matches; a prompt has none.
        if "regex" not in r or ("path" in r and re2.search(r["path"], "") is None):
            skipped.append(r["id"])
            continue
        rules.append(
            Rule(
                id=r["id"],
                regex=re2.compile(r["regex"]),
                keywords=tuple(k.lower() for k in r.get("keywords", [])),
                entropy=float(r.get("entropy", 0.0)),
                secret_group=int(r.get("secretGroup", 0)),
                allowlists=tuple(_allowlist(a) for a in r.get("allowlists", [])),
            )
        )
    glob = cfg.get("allowlists", [])
    if "allowlist" in cfg:
        glob = [*glob, cfg["allowlist"]]
    if any("targetRules" in a for a in glob):
        raise ValueError("gitleaks allow-list targetRules not supported")
    return RuleSet(tuple(rules), tuple(_allowlist(a) for a in glob), tuple(skipped))


@cache
def rule_set() -> RuleSet:
    raw = resources.files("prompt_privacy.detectors").joinpath("gitleaks_rules", RULES_FILE).read_bytes()
    return parse(raw)


def find(text: str, rs: RuleSet | None = None) -> list[tuple[int, int, str]]:
    """(start, end, rule id) of every secret the Gitleaks rules (`rs`, default the pinned set) report."""
    rs = rs or rule_set()
    low = text.lower()
    present = {k for k in {k for r in rs.rules for k in r.keywords} if k in low}
    hits: list[tuple[int, int, str, int, str]] = []  # start, end, rule id, start of the match's line, secret
    for rule in rs.rules:
        if rule.keywords and not any(k in present for k in rule.keywords):
            continue
        for m in rule.regex.finditer(text):
            ms, me = m.span()
            whole = text[ms:me]
            ms += len(whole) - len(whole.lstrip("\n"))
            me -= len(whole) - len(whole.rstrip("\n"))
            if ms >= me:
                continue
            ss, se = ms, me
            if rule.secret_group:
                ss, se = m.span(rule.secret_group)
                if ss < 0:
                    continue
            else:
                for g in range(1, rule.regex.groups + 1):
                    gs, ge = m.span(g)
                    if ge > gs:
                        ss, se = gs, ge
                        break
            secret = text[ss:se]
            if rule.entropy and shannon_entropy(secret) <= rule.entropy:
                continue
            line_start = text.rfind("\n", 0, ms) + 1
            line_end = text.find("\n", me)
            line = text[line_start : len(text) if line_end < 0 else line_end]
            match = text[ms:me]
            if any(a.allows(secret, match, line) for a in (*rs.allowlists, *rule.allowlists)):
                continue
            hits.append((ss, se, rule.id, line_start, secret))
    # As Gitleaks' `filter`: a generic finding gives way to a specific rule's finding on the same line
    # whose secret contains it.
    specific: dict[int, list[tuple[str, str]]] = {}
    for _, _, rid, ls, sec in hits:
        if "generic" not in rid.lower():
            specific.setdefault(ls, []).append((rid, sec))
    return [
        (s, e, rid)
        for s, e, rid, ls, sec in hits
        if "generic" not in rid.lower() or not any(r != rid and sec in s2 for r, s2 in specific.get(ls, ()))
    ]

"""Stage 1 secret rules (ADR-0005). Offline only: secrets are never validated against their issuer.

Rules are owned and versioned here. Each rule is (id, regex). The regex runs on the shadow text;
group "s" (if present) marks the secret itself, otherwise the whole match is the secret. A rule may
also have a value check (`VALUE_CHECKS`): a value that fails it is not reported. Gitleaks' rules run
beside these (`gitleaks.py`).
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Callable

# 2: `assignment` values with a Gitleaks stop word dropped. 3: instead, values that are placeholders,
# name a kind of credential, or are templates or code (Gitleaks' 1,448 words also drop real passwords:
# 44 of Nemotron's); Basic, Bearer and NTLM/Negotiate authorization rules.
RULES_VERSION = 3

# Words that mark a value as a stand-in, not a credential. Kept short on purpose: a word that also
# occurs in real passwords (`test`, `admin`, `account`) would drop real ones.
PLACEHOLDER_WORDS = (
    "change", "example", "sample", "dummy", "fake", "placeholder", "your", "xxx", "todo", "fixme",
    "redacted", "replace", "insert",
)  # fmt: skip
# A value that names a kind of credential is a name or a stand-in (`ACCESS_TOKEN=access_token_here`).
# On CredData these words removed 1,300 spans on lines reviewed as no credential or not labelled, for
# 6 real ones; on Nemotron they cost 2 real passwords (`Password123`-style).
CREDENTIAL_KIND_WORDS = ("token", "passw", "secret", "auth", "access", "credential")
_TEMPLATE = re.compile(r"^\$[A-Za-z_{(]|^%\(|^%[A-Za-z_]+%$|^<[^>]*>$|\$\{|\{\{|\}\}|#\{")
# Code, not a literal: an unquoted value with a call or an index (`get_token(request)`, `os.environ[`,
# `[]byte{`, `a.b().c(x),`). On CredData 517 unquoted bracket values that are not otherwise dropped
# hold 1 credential; an unquoted password with a bracket in it is the cost (1 on Gretel too).
_CODE_REFERENCE = re.compile(r"[(\[]")


def is_placeholder(value: str, quoted: bool) -> bool:
    """A `KEY=value` value that is not a credential: a placeholder word or a word naming a kind of
    credential, a template (`${X}`, `{{x}}`, `<x>`, `$X`), three or fewer distinct characters, or,
    when not quoted, code (`os.environ[...]`, `get_token(...)`)."""
    low = value.lower()
    return (
        any(w in low for w in PLACEHOLDER_WORDS + CREDENTIAL_KIND_WORDS)
        or _TEMPLATE.search(value) is not None
        or len(set(value)) <= 3
        or (not quoted and _CODE_REFERENCE.search(value) is not None)
    )


def basic_credentials(value: str) -> bool:
    """HTTP Basic: base64 of `user:password` (printable, both parts non-empty)."""
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), validate=True)
        text = raw.decode("ascii")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return False
    user, sep, password = text.partition(":")
    return bool(sep and user and password) and text.isprintable()


def token_like(value: str) -> bool:
    """A bearer token: letters and digits both present (prose after "bearer" has no digits)."""
    return any(c.isdigit() for c in value) and any(c.isalpha() for c in value)


# Value checks per rule: (value, character before it) -> keep. Applied in `base.detect`.
VALUE_CHECKS: dict[str, Callable[[str, str], bool]] = {
    "assignment": lambda v, before: not is_placeholder(v, before in "\"'"),
    "basic_auth": lambda v, _: basic_credentials(v),
    "bearer_token": lambda v, _: token_like(v),
}

SECRET_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key_id", re.compile(r"\b(?P<s>(?:AKIA|ASIA)[0-9A-Z]{16})\b")),
    ("github_token", re.compile(r"\b(?P<s>gh[pousr]_[A-Za-z0-9]{36,255})\b")),
    ("github_fine_grained_pat", re.compile(r"\b(?P<s>github_pat_[A-Za-z0-9_]{22,255})\b")),
    ("anthropic_api_key", re.compile(r"\b(?P<s>sk-ant-[A-Za-z0-9_\-]{20,})")),
    ("openai_api_key", re.compile(r"\b(?P<s>sk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,})")),
    ("slack_token", re.compile(r"\b(?P<s>xox[abposr]-[A-Za-z0-9-]{10,})\b")),
    ("google_api_key", re.compile(r"\b(?P<s>AIza[0-9A-Za-z_\-]{35})\b")),
    ("stripe_secret_key", re.compile(r"\b(?P<s>[sr]k_(?:live|test)_[0-9A-Za-z]{16,})\b")),
    (
        "private_key_block",
        re.compile(
            r"(?P<s>-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----[\s\S]+?"
            r"-----END (?:[A-Z0-9]+ )?PRIVATE KEY-----)"
        ),
    ),
    ("jwt", re.compile(r"\b(?P<s>eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})")),
    (
        "url_credentials",
        re.compile(r"\b[a-z][a-z0-9+.\-]*://[^\s:/@]+:(?P<s>[^\s/@]{3,})@", re.IGNORECASE),
    ),
    (
        "assignment",
        re.compile(
            r"(?im)^[ \t]*(?:export[ \t]+)?[A-Z0-9_]*(?:SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY|PRIVATE_?KEY)"
            r"[A-Z0-9_]*[ \t]*[=:][ \t]*[\"']?(?P<s>[^\s\"']{8,})[\"']?"
        ),
    ),
    # HTTP authorization schemes, with or without an `Authorization:` header name before them.
    ("basic_auth", re.compile(r"(?i)\bbasic[ \t]+(?P<s>[A-Za-z0-9+/]{6,}={0,2})(?![A-Za-z0-9+/=])")),
    ("bearer_token", re.compile(r"(?i)\bbearer[ \t]+(?P<s>[A-Za-z0-9._~+/-]{16,}=*)(?![A-Za-z0-9._~+/=-])")),
    (
        "ntlm_negotiate",
        re.compile(r"(?i)\b(?:ntlm|negotiate)[ \t]+(?P<s>(?:TlRMTVNTUA|YII)[A-Za-z0-9+/]{8,}={0,2})"),
    ),
)

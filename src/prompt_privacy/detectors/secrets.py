"""Stage 1 secret rules (ADR-0005). Offline only: secrets are never validated against their issuer.

Rules are owned and versioned here. Each rule is (id, regex). The regex runs on the shadow text;
group "s" (if present) marks the secret itself, otherwise the whole match is the secret.
"""

from __future__ import annotations

import re

RULES_VERSION = 1

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
)

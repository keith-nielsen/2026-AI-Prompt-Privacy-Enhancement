# Contributing

Thanks for your interest. PPE is in the design phase; discussion of the ADRs in `docs/design/` is the
most useful contribution right now.

## Ground rules

1. **No real personal data anywhere** — not in issues, PRs, tests, fixtures, screenshots or logs.
   Use synthetic values only: reserved ranges (`example.com`, `192.0.2.0/24`, `555-0100`…) or
   identifiers with deliberately invalid check digits. The test corpus is generated from a fixed seed.
2. **No live secrets**, ever. Secret-detector tests use format-valid fakes (e.g. AWS-style
   `…EXAMPLE` keys).
3. **Mechanism, not policy** (ADR-0012): new features ship as mechanisms with a default, a stated
   trade-off and a test that proves them. Don't hard-code an organisation's policy.
4. **Invariants are not negotiable** (ADR-0012 §2): changes that would let PPE persist or emit
   plaintext protected values, hand a person a decryption key, or relax fail-closed behaviour outside
   `lab` will not be merged.
5. Security issues go through private reporting (see `SECURITY.md`).

## Development

```bash
uv venv --python 3.12 .venv && uv pip install --python .venv/bin/python -e ".[dev]"
.venv/bin/ruff check src tests && .venv/bin/ruff format --check src tests && .venv/bin/mypy && .venv/bin/pytest
.venv/bin/ppe verify
```

A knob without a proving test isn't done (ADR-0012). Source files must not contain invisible or
bidi control characters (`tests/test_source_hygiene.py`, Trojan Source guard); write `"\u200b"`.

## Decision records

Significant design changes are proposed as a new ADR (`docs/design/ADR-NNNN-*.md`), or as an
amendment section in an existing ADR, citing sources in `docs/sources/`.

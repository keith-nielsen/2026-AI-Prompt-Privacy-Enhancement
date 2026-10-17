# Security Policy

## Status

PPE is **pre-alpha** (v0.1.0.dev2): the detectors, swap/restore, the sealed audit log, the CLI and a
shadow-mode proxy (`ppe serve`) are built and tested; much of the design is not built yet (see the
README's "Built and designed" table). Do not rely on it to protect real data yet. Reports on the code,
on the design documents, and on gaps between the two are all welcome. Known open findings are listed
in `docs/review/2026-10-16-product-review.md`.

## Reporting a vulnerability or design flaw

**Please do not file public issues for security vulnerabilities.**

Use **GitHub Private Vulnerability Reporting**:

1. Open the repository's **Security** tab
2. Click **Report a vulnerability**
3. Describe the issue, its impact, the version or commit, and which document or component it affects

GitHub notifies the maintainer directly. There is no public security e-mail address.

## Scope notes

- PPE is a protection mechanism, **not anonymisation**: masked prompts remain personal data.
  Reports that a provider could re-identify someone from indirect identifiers are known residual
  risks (see `docs/threat-model.md`), but concrete new attacks are welcome.
- Never include real personal data or live credentials in a report. Use synthetic examples.

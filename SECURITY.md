# Security Policy

## Status

PPE is in the **design phase**: this repository contains design documents only, no executable code
yet. Design flaws are still security issues and are welcome.

## Reporting a vulnerability or design flaw

**Please do not file public issues for security vulnerabilities.**

Use **GitHub Private Vulnerability Reporting**:

1. Open the repository's **Security** tab
2. Click **Report a vulnerability**
3. Describe the issue, its impact, and which document or component it affects

GitHub notifies the maintainer directly. There is no public security e-mail address.

## Scope notes

- PPE is a protection mechanism, **not anonymisation**: masked prompts remain personal data.
  Reports that a provider could re-identify someone from indirect identifiers are known residual
  risks (see `docs/threat-model.md`), but concrete new attacks are welcome.
- Never include real personal data or live credentials in a report. Use synthetic examples.

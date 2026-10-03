# Prompt Privacy Enhancement (PPE)

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-phase%201%20core%20(no%20proxy%20yet)-yellow)](docs/design/PLAN.md)
[![ADRs](https://img.shields.io/badge/ADRs-0001--0012-informational)](docs/design/)

**A practical, testable privacy harness for LLM traffic.** PPE sits on the paths between your
prompts and your models and keeps identifiers and secrets from leaving your machine in clear text,
while keeping answers useful and leaving tamper-evident, attacker-proof evidence of what happened.

> **Status: phase 1 core.** The deterministic detectors, surrogate swap/restore, the fully sealed
> 2-of-2 post-quantum audit log, the synthetic corpus, the benchmark and the `ppe` CLI work and are
> tested. The proxy that puts them on real traffic (phase 2), the span models and the arbiter are not
> built yet. Nothing here is a certified control.

## Try it (phase 1)

```bash
uv venv --python 3.12 .venv && uv pip install --python .venv/bin/python -e ".[dev]"
.venv/bin/pytest                      # unit, property and adversarial tests
.venv/bin/ppe verify                  # conformance self-tests (synthetic data only)
.venv/bin/ppe bench                   # Stage 1 detection rates per type on the synthetic corpus
.venv/bin/ppe explain --policy policies/lab.yaml   # what a configuration protects and gives up
echo "NRIC S1234567D, card 4111 1111 1111 1111" | .venv/bin/ppe scan       # values never printed
echo "NRIC S1234567D, card 4111 1111 1111 1111" | .venv/bin/ppe mask       # surrogates
.venv/bin/ppe audit keygen --dev-token && .venv/bin/ppe audit append '{"event":"demo"}' \
  && .venv/bin/ppe audit verify && .venv/bin/ppe audit open --dev-token   # "1234" = dev token stand-in
```

Benchmark numbers come from a synthetic corpus written alongside the detectors. Treat them as a
regression floor, not as evidence of real-world accuracy (see `bench/`).

## What it does (by design)

- **Verified zones.** Only a verified loopback endpoint on the same host counts as local: address,
  no proxy, an attested terminal server, and peer-process checks. Everything else is cloud.
  ([ADR-0001](docs/design/ADR-0001-trust-zones.md))
- **Egress guard.** Cloud-bound traffic (from stand-alone clients or from a LiteLLM router) crosses one
  small PPE proxy that host egress rules make the only way out.
  ([ADR-0006](docs/design/ADR-0006-interface-and-topology.md))
- **Swap and restore.** Real values are replaced by deterministic, plausible **surrogates**: provably
  not real where possible (reserved ranges, invalid check digits). The originals are restored in the
  reply, including streamed text and tool-call arguments, without breaking prompt caching or preserved
  thinking. ([ADR-0002](docs/design/ADR-0002-swap-and-restore.md), [ADR-0008](docs/design/ADR-0008-surrogate-values.md))
- **Detection ensemble.** Deterministic rules, two independent span models, and a local LLM arbiter
  using llama.cpp *parallel-decision*. The arbiter can only tighten protection.
  ([ADR-0005](docs/design/ADR-0005-detection-ensemble.md))
- **Observation plane.** See how much sensitive data you actually handle, even on approved local
  flows and at data sources, without modifying any of it.
  ([ADR-0007](docs/design/ADR-0007-observation-plane.md))
- **No breadcrumbs.** Every audit record is fully sealed (2-of-2: machine key + token key, hybrid
  post-quantum wraps). Metrics are health-only and alerts opaque. Key destruction shreds retention.
  ([ADR-0003](docs/design/ADR-0003-retention-and-keys.md), [ADR-0010](docs/design/ADR-0010-fully-sealed-audit.md))
- **Break-glass.** Two approvers release a scoped, time-bound decryption *session* (never a key) to one
  investigator; it auto-closes and re-arms. Hardened against real-world failures (H1–H13).
  ([ADR-0011](docs/design/ADR-0011-break-glass-release.md))
- **Mechanism, not policy.** Invariants, a catalogue of knobs with stated trade-offs, reference
  profiles, `ppe explain` and `ppe verify`, so you can right-size it and prove your configuration.
  ([ADR-0012](docs/design/ADR-0012-mechanism-not-policy.md), **read first**)

## Limits, stated plainly

- PPE is a **protection mechanism, not anonymisation**. Masked prompts remain personal data
  (PDPC, EDPB). Indirect identifiers and context still reach the provider.
- Detection is probabilistic. Published per-class detection rates (from a synthetic corpus) will be
  the honest measure.
- Root on the host defeats local controls.

## Read

| Document | |
|---|---|
| [docs/design/PLAN.md](docs/design/PLAN.md) | what it is, layout, phases, open decisions |
| [docs/design/](docs/design/) | ADR-0001 … ADR-0012 |
| [docs/threat-model.md](docs/threat-model.md) | assets, adversaries, STRIDE, test scenarios |
| [docs/controls-mapping.md](docs/controls-mapping.md) | NIST SP 800-53 / AI 600-1, PDPC/PDPA, CSA, EDPB, OWASP |
| [docs/research/](docs/research/) | research report; break-glass case studies (defeated / lockout / after-the-fact; quantum and AI) |
| [docs/sources/](docs/sources/README.md) | primary-source notes |

## Relationship to Kent

[Kent](https://github.com/keith-nielsen/2026-AI-Harness-Kent) will be one integration. PPE is built
for stand-alone users first, and nothing Kent-specific lives in the core.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) (no real personal data, ever) and [SECURITY.md](SECURITY.md)
(private vulnerability reporting).

Licensed under the [Apache License 2.0](LICENSE).
</content>
</invoke>
<invoke name="Bash">
<parameter name="command">cd ~/Documents/repo/prompt-privacy-enhancement && python3 - <<'EOF'
import re,os
for f in ['README.md','CONTRIBUTING.md','SECURITY.md']:
    for m in re.finditer(r'\]\(([^)#\s]+)(#[^)]*)?\)', open(f).read()):
        t=m.group(1)
        if not t.startswith('http') and not os.path.exists(t): print("BROKEN",f,t)
print("links ok")
EOF
git add README.md LICENSE NOTICE CITATION.cff SECURITY.md CONTRIBUTING.md && git commit -q -F - <<'EOF'
docs: repository anchor files (README, Apache-2.0 LICENSE, NOTICE, SECURITY, CONTRIBUTING, CITATION)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
git branch -f main HEAD 2>/dev/null || git branch main; git log --oneline main -3; git branch
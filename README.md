# Prompt Privacy Enhancement (PPE)

[![Pre-alpha](https://img.shields.io/badge/Maturity-pre--alpha-red)](#prompt-privacy-enhancement-ppe)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-phase%202a%20(shadow--mode%20proxy)-yellow)](docs/design/PLAN.md)
[![ADRs](https://img.shields.io/badge/ADRs-0001--0013-informational)](docs/design/)

**A practical, testable privacy harness for LLM traffic.** PPE sits on the paths between your
prompts and your models and keeps identifiers and secrets from leaving your machine in clear text,
while keeping answers useful and leaving sealed, hash-chained evidence of what happened (signed
checkpoints are planned; see the limits below).

> [!WARNING]
> **Pre-alpha.** Interfaces, file formats, the audit record format and defaults will change without
> notice or migration. Do not rely on PPE to protect real personal data or secrets yet: shadow mode
> observes, it does not mask.

> **Status: v0.1.0.dev1, phase 2a.** The deterministic detectors, surrogate swap/restore,
> the fully sealed 2-of-2 post-quantum audit log (hash-chained; signed checkpoints planned), the
> synthetic corpus, the benchmark and the `ppe` CLI work and are tested. `ppe serve` is a loopback proxy for the Anthropic Messages API in
> **shadow mode**: it forwards traffic unchanged and records sealed findings; it does **not** mask
> yet (masking is phase 4). Not yet validated with a real client against a real provider. The span
> models and the arbiter are not built yet. Nothing here is a certified control.

## Try it

```bash
uv venv --python 3.12 .venv && uv pip install --python .venv/bin/python -e ".[dev]"
.venv/bin/pytest                      # unit, property and adversarial tests
.venv/bin/ppe verify                  # conformance self-tests (synthetic data only)
.venv/bin/ppe bench                   # Stage 1 detection rates per type on the synthetic corpus
.venv/bin/ppe explain --policy policies/lab.yaml   # what a configuration protects and gives up
.venv/bin/ppe evaluate fetch nemotron-pii --data-dir ~/datasets   # pinned public dataset (needs .[bench])
.venv/bin/ppe evaluate run nemotron-pii --data-dir ~/datasets     # same scoring protocol for every system
echo "NRIC S1234567D, card 4111 1111 1111 1111" | .venv/bin/ppe scan       # values never printed
echo "NRIC S1234567D, card 4111 1111 1111 1111" | .venv/bin/ppe mask       # surrogates
.venv/bin/ppe audit keygen --dev-token && .venv/bin/ppe audit append '{"event":"demo"}' \
  && .venv/bin/ppe audit verify && .venv/bin/ppe audit open --dev-token   # "1234" = dev token stand-in
```

Shadow-mode proxy (forwards unchanged, records sealed findings; loopback only):

```bash
.venv/bin/ppe audit keygen --dev-token          # once
.venv/bin/ppe serve                             # 127.0.0.1:8787 -> https://api.anthropic.com
ANTHROPIC_BASE_URL=http://127.0.0.1:8787 claude # any Anthropic Messages client
.venv/bin/ppe audit verify && .venv/bin/ppe audit open --dev-token
```

Benchmark numbers come from a synthetic corpus written alongside the detectors. Treat them as a
regression floor, not as evidence of real-world accuracy (see `bench/`). The first external
measurement, on NVIDIA's public synthetic Nemotron-PII test split with a published scoring protocol,
is in [`bench/2026-10-16-nemotron-pii.md`](bench/2026-10-16-nemotron-pii.md): e.g. e-mail recall 0.995,
IPv4 1.000, phone 0.917 (typed precision 0.535; 0.993 with `phone_context: required`); 14% of all
labelled spans covered, because names, addresses and most ID types need span models (not built).

## Built and designed

| Area | Built (v0.1.0.dev1) | Designed, not built |
|---|---|---|
| Detection | Stage 0 shadow text; Stage 1 rules: 12 secret types, checksummed identifiers (SG NRIC/FIN, cards, IBAN), e-mail, phone, IP addresses, operator dictionary | span models, arbiter (ADR-0005) |
| Swap and restore | surrogates with format transfer; closed-world restore (`ppe mask`) | in the proxy; streaming restore R5; context-aware restore (phase 4) |
| Proxy | `ppe serve`: loopback, Anthropic Messages API, shadow mode (observes, never modifies) | OpenAI formats, reply-flow observation, masking, bearer token / UNIX socket |
| Audit | 2-of-2 sealed records, hash chain, shared-writer locking, `ppe audit verify/open` | `auditd` account, signed checkpoints, retention / crypto-shredding job (ADR-0003/0004) |
| Observation | sealed per-request records with keyed digests and counted gaps | exposure ledger, sensors, alerts (ADR-0007) |
| Configuration | policy schema, profiles `lab`/`personal`/`team`, `ppe explain`, `ppe verify` | zone verification L1-L3 (ADR-0001), break-glass broker (ADR-0011) |

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
- The audit log is **hash-chained but not yet signed**. The chain detects edits inside the log; it does
  not detect truncation of its tail or a log rebuilt from scratch by someone who can write the file
  (on a stand-alone install: you, or malware running as you). Signed checkpoints and a separate
  writer account (ADR-0004) close this; until then treat the log as evidence against mistakes and
  outsiders, not against the account that writes it.

## Read

| Document | |
|---|---|
| [docs/design/PLAN.md](docs/design/PLAN.md) | what it is, layout, phases, open decisions |
| [docs/design/](docs/design/) | ADR-0001 … ADR-0013 |
| [docs/threat-model.md](docs/threat-model.md) | assets, adversaries, STRIDE, test scenarios |
| [docs/controls-mapping.md](docs/controls-mapping.md) | NIST SP 800-53 / AI 600-1, PDPC/PDPA, CSA, EDPB, OWASP |
| [docs/research/](docs/research/) | research report; break-glass case studies (defeated / lockout / after-the-fact; quantum and AI) |
| [docs/sources/](docs/sources/README.md) | primary-source notes |
| [docs/review/](docs/review/2026-10-16-product-review.md) | product review 2026-10-16: findings, conformance suite, roadmap |

## Relationship to Kent

[Kent](https://github.com/keith-nielsen/2026-AI-Harness-Kent) will be one integration. PPE is built
for stand-alone users first, and nothing Kent-specific lives in the core.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) (no real personal data, ever) and [SECURITY.md](SECURITY.md)
(private vulnerability reporting).

Licensed under the [Apache License 2.0](LICENSE).

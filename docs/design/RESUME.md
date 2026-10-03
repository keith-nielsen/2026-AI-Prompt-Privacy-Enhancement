# Resume card — Prompt Privacy Enhancement (PPE)

## Status (2026-10-03): PHASE 1 CORE BUILT AND PUBLISHED — next is phase 2 (the proxy)

- GitHub (public, Apache-2.0): https://github.com/keith-nielsen/2026-AI-Prompt-Privacy-Enhancement
  — `main` = `922a99e` (also on branch `phase-1-core`; design history on `docs/design-research-adrs`).
  Local: `~/Documents/repo/prompt-privacy-enhancement`, branch `main`, clean.
- Profile index `keith-nielsen/keith-nielsen` (`README.md`, branch `master`) lists PPE between Kent and
  VMM, status "Phase 1 core · detectors, swap/restore, sealed audit". Update it when status changes.
- Commit/push only when the operator asks (they have, for each step so far). Branch first, then
  fast-forward `main` so the published README matches the code.

## Quick start (verify the build before changing anything)

```bash
cd ~/Documents/repo/prompt-privacy-enhancement
~/ai-env/bin/uv venv --python 3.12 .venv   # only if .venv is missing
~/ai-env/bin/uv pip install --python .venv/bin/python -e ".[dev]"
.venv/bin/ruff check src tests && .venv/bin/ruff format --check src tests && .venv/bin/mypy && .venv/bin/pytest
.venv/bin/ppe verify        # expect 10/10
.venv/bin/ppe bench         # Stage 1 rates (regression floor, not real-world evidence)
```

Expected at `922a99e`: ruff + strict mypy clean, **56 tests pass**, **10/10 self-checks**.

## Read first (in order)

1. This card.
2. [`ADR-0012`](ADR-0012-mechanism-not-policy.md) — governs how every other ADR is read (mechanism,
   not policy; invariants vs knobs; trade-offs; proving tests).
3. [`PLAN.md`](PLAN.md) — layout, phases, §6 decisions (list below), §7 hard problems.
4. ADR-0001…0011 (all status *proposed*; the operator has decided many items, recorded in PLAN §6).
5. [`../research/`](../research/) — research report + break-glass case studies;
   [`../threat-model.md`](../threat-model.md), [`../controls-mapping.md`](../controls-mapping.md);
   [`../sources/README.md`](../sources/README.md).

## What exists (phase 1)

`src/prompt_privacy/`: `core/` (types, checksums incl. SG NRIC/FIN M-series, Stage 0 shadow text,
normalise, keys, surrogates, vault, engine), `detectors/` (12 secret rules, structured patterns,
operator dictionary, overlap resolution), `audit/` (2-of-2 sealed envelope, hybrid ML-KEM-768+X25519
HPKE from `cryptography` 50, padding buckets, hash-chained log; dev token `"1234"` via Argon2id,
refused outside `lab`), `corpus/` (synthetic generator, fixed seed, evasion variants, known gaps),
`bench.py`, `knobs.py` (ADR-0012 catalogue → `ppe explain`), `policy.py` + `schemas/` + `policies/`
(lab/personal/team examples), `selftest.py` (`ppe verify`), `cli/main.py` (`ppe scan|mask|corpus|
bench|explain|verify|audit keygen|append|verify|open`). Bench output: `bench/2026-10-02-stage1-rules.txt`.

Findings while building (keep): phone false positives from dates/ISBNs/order numbers → setting
`detection.phone_context` (optional: recall 1.000 / precision ~0.92 — default, recall first;
required: recall ~0.85 / precision 1.000); R3 round trip needs **format transfer** (a surrogate is a
canonical value rendered into each occurrence's format); `ruff format` once wrote literal bidi /
zero-width characters into source → code points + `tests/test_source_hygiene.py` (Trojan Source guard).

## Not built yet

Phase 2 proxy (OpenAI + Anthropic wire formats, SSE streaming restore R5, ingress/egress/observe
listeners, Claude Code compatibility per `sources/claude-code-gateway.md`); zone verification L1–L3;
signed C2SP checkpoints; retention / crypto-shredding job; per-class swap forms; observation plane and
sensors; Stage 2 span models (GLiNER2-PII, OpenAI Privacy Filter) and the parallel-decision arbiter
(GPU bench needs operator permission); break-glass broker; LiteLLM advisory callback; Kent wiring.

## Open decisions (PLAN §6 — recommendation first)

2. `on_error` in hardened: keep local if a loopback target exists, else block — confirm.
3. Default "special" (keep-local) classes for `sg-pdpa`: health, financial detail, biometric,
   children, legal matter — confirm.
4. Audit retention: 12 months of period-key life (deployer writes the rationale).
5. Kent conversation id: Hermes session id in `x-ppe-conversation-id`, forwarded by LiteLLM, trusted
   only from LiteLLM's peer credentials.
6. Names: PyPI `prompt-privacy-enhancement`, import `prompt_privacy`, CLI `ppe` (in use) — confirm.
7. Topology: egress guard + advisory LiteLLM callback (ADR-0006) — confirm.
8. Arbiter hosting: dedicated small GGUF on its own fork llama-server (recommended) vs Kent's main
   llama-server — decide after the bench.
9. `suppress_model_fp`: lab/standard only, never hardened (recommended) vs never.
10. Provider credentials: pass-through (recommended stand-alone) vs PPE holds keys.
11. Non-Latin-script content until a measured model exists: keep local / block in hardened.
12. Meaning/origin of "Jev" in "Jev-style parallel decisions".
13. Observation: bulk-volume alert baselines; whether Gents declare `data_classes`.
14. Surrogates: SG phone reserved range (ask IMDA); default `min_guarantee` per profile;
    `announce: system_note` (bench decides).
15. Kent audit key custody (HSM / smart card / air-gapped laptop); period length (monthly/quarterly).
16. Second-token escrow or 2-of-3 across auditors; production finding counters (proposal: never).
17. Break-glass example defaults: approver roster ≥ 3, session 4 h / max 12 h, emergency path on/off,
    broker on a separate host/VM (adopter knobs per ADR-0012).

## Next steps (recommended order)

1. Phase 2 proxy, test-first: Anthropic Messages + OpenAI Chat/Responses wire formats, streaming
   restore (R5) with chunk-boundary holdback, `x-claude-code-session-id` as conversation key, error
   bodies in the client's format with opaque refs; test with Claude Code against a fake upstream
   (no real cloud calls).
2. Signed C2SP checkpoints + `ppe audit verify` signature check; retention/shredding job.
3. Zone verification (L1 address/no-proxy/attestation; L2 `SO_PEERCRED`) for the observe/egress hops.
4. With operator permission when the GPU is free: Stage 2 span models + parallel-decision arbiter bench.

## History

### Operator's direction (keep)

- **Stand-alone users first.** Many more people will screen prompts to cloud providers without Kent
  than with it. Judge every design choice by the stand-alone user; Kent is one integration
  (assume every Kent install enables PPE). Nothing Kent-specific in the core.
- The §6 decisions are "easy" and wait for the start of the real work. The effort goes into §7:
  on-the-fly swap/restore (the operator calls it encrypt/decrypt), data retention, audit.
- Repo naming: GitHub `2026-AI-<Title-Case>`, local dir lowercase without the prefix.
- Licence assumption: Apache-2.0 like Kent (confirm when starting).

### How we got here (context not in the other files)

- Started as Kent's "egress guard" TODO (harness-kent `TODO.md`, Features), which closes Kent's
  2026-09-28 audit finding F-08 (no DLP/redaction before prompts leave the host). Generalised into a
  separate package the same day.
- Rejected: LiteLLM's built-in Presidio hook for masking (tokens `<PERSON_1>` numbered by position:
  can collide within a conversation, no audit value) and its content filter for PII (mask is one-way).
  Both stay useful as references; Presidio's Analyzer is reused as a detector over HTTP.
- Token design came from the operator's wish for forensically traceable anchors. The operator first
  proposed `PERSON_<datestamp><container><pid>`; we moved the metadata into a local audit record and
  derived the token from a keyed hash of the value, so tokens stay stable within a conversation (no
  collisions, prompt cache keeps hitting), are unlinkable across conversations, and leak no internal
  metadata to the provider.
- Key facts verified by reading code (not by running it): LiteLLM 1.100.1 has
  `async_pre_call_deployment_hook` (after deployment selection, before send), which settles "mask
  only when `auto` resolved to a cloud tier" for the LiteLLM adapter. See `sources/litellm-hooks.md`.
- Tirith and Hermes `redact_secrets` (Kent) cover commands and secret-shaped tool output only — no
  PII; nothing screens the gateway → cloud path today.
- Regulatory reading so far (SG focus, EU for comparison): masked prompts are still personal data;
  PDPC's GenAI guidelines §8.3/§9.3–9.5 describe exactly this kind of safeguard and ask for detection
  metrics and written policies; the Basic Anonymisation guide's pseudonym rules and breach scenarios
  shape the key and incident design. Agent-specific PDPC guidance is promised but not issued.

### Overnight pass and same-day reviews, 2026-10-02 (planning only)

Operator answers that night: local zone = **loopback only**; added baseline = **NIST / US federal**;
"parallel decision mode" = `thecodacus/llama.cpp@parallel-decision` (`POST /v1/decision`);
deliverable = docs only; **do not touch Kent's llama-server (:8081, overnight test) or LiteLLM
(:4000)**; model downloads allowed for analysis only (only model cards were fetched).

Main outcomes: egress-guard topology proposed (ADR-0006, changes PLAN §3/§4); byte-stable history
is a hard requirement (preserved thinking, prompt caching); detection = rules + two span models
(GLiNER2-PII, OpenAI Privacy Filter shortlisted) + parallel-decision arbiter under a ratchet rule;
crypto-shredding with independent random period keys; Presidio moved to `data-privacy-stack`.
Open operator decisions: PLAN §6 items 2–13.

Follow-up the same day: operator asked to monitor approved/local, unmodified traffic too ("know what
we are actually protecting") → ADR-0007 observation plane: PPE on both router legs (observe on
loopback, enforce on cloud), data-source sensors (Hermes `post_tool_call` plugin, Gent tools wrapper),
per-identifier digests, exposure ledger with coverage, threshold alerts, never blocks local traffic.
Second follow-up: audit is itself a target → ADR-0009 (occurrence records in clear incl. access
principal; value-derived digests HPKE-sealed to an offline period key; offline four-eyes lookups;
shred = destroy the private key). Egress swap = plausible surrogates for all classes → ADR-0008
(reserved ranges / invalid-checksum constructions where possible; names may match real people).
Third follow-up: clear occurrence records are attacker targeting info → ADR-0010: entire records
sealed, 2-of-2 (machine public key + token public key; dev token = string "1234"); health-only
metrics, opaque alerts/errors; ledger and investigations only via `ppe audit open`.
Fourth follow-up: production usability → ADR-0011 break-glass: 2 approvers sign one exact scoped
request, TPM policy unlocks period keys inside hardware, 1 investigator gets a time-bound broker
session (live tail / monitoring datasource), auto-close revokes and re-arms. No one ever holds a key.
Fifth follow-up: real-world validation → `research/2026-10-02-break-glass-case-studies.md` (defeated /
lockout / after-the-fact cases; PQ and AI trends) with hardening H1–H13 — **all adopted** by the operator (now requirements in ADR-0011).


Later on 2026-10-02/03: ADR-0012 (mechanism, not policy) adopted; break-glass parameters became adopter
knobs; repo published (public) with README/LICENSE/SECURITY/CONTRIBUTING/CITATION; phase 1 core built,
committed (`922a99e`) and pushed; profile index updated twice.

## Working agreements

Test before claiming; mark anything untested. Draft first, operator corrects. When asking for a
decision, list every option in the reply (not just IDs and a file path). Planning mode means docs only:
never run models or touch local services (Kent's llama-server :8081 runs overnight tests; LiteLLM
:4000). No real personal data anywhere in the repo (synthetic only). Never put invisible/bidi
characters in source. Ship mechanisms + defaults + trade-offs + tests; adopters set policy.

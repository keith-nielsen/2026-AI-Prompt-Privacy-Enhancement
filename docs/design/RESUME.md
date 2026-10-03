# Resume card — Prompt Privacy Enhancement (PPE)

## Status: RESEARCHED, awaiting operator review (overnight pass 2026-10-02)

Nothing is built. Local repo only: `git init` on `main`, **nothing committed**, no GitHub repo yet
(intended: `keith-nielsen/2026-AI-Prompt-Privacy-Enhancement`; local dir
`~/Documents/repo/prompt-privacy-enhancement`). Commit or create on GitHub only when the operator asks.

## Read first (in order)

1. This card.
1a. [`../research/2026-10-02-research-report.md`](../research/2026-10-02-research-report.md) — the
   overnight research pass: findings, plan changes, decisions still open.
1b. ADR-0001…0012 in this folder (read **ADR-0012 first**: it governs how the others are read) (all *proposed*; 0007 observation plane, 0008 surrogate values,
   0009 sealed audit — added after the operator's reviews the same day), [`../threat-model.md`](../threat-model.md) draft 0,
   [`../controls-mapping.md`](../controls-mapping.md) draft 0.
2. [`PLAN.md`](PLAN.md) — what it is, audience, layout, core design, Kent layering, phases,
   §6 deferred decisions, **§7 the hard problems** (swap/restore, retention, audit).
3. [`../sources/README.md`](../sources/README.md) — index of primary sources, hashes, what is still
   unread; one note per source with quotes and implications.

## Operator's direction (keep)

- **Stand-alone users first.** Many more people will screen prompts to cloud providers without Kent
  than with it. Judge every design choice by the stand-alone user; Kent is one integration
  (assume every Kent install enables PPE). Nothing Kent-specific in the core.
- The §6 decisions are "easy" and wait for the start of the real work. The effort goes into §7:
  on-the-fly swap/restore (the operator calls it encrypt/decrypt), data retention, audit.
- Repo naming: GitHub `2026-AI-<Title-Case>`, local dir lowercase without the prefix.
- Licence assumption: Apache-2.0 like Kent (confirm when starting).

## How we got here (context not in the other files)

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

## Phase 1 core — built 2026-10-02 (uncommitted at time of writing)

`src/prompt_privacy/`: `core/` (types, checksums incl. SG NRIC/FIN M-series, Stage 0 shadow, normalise,
keys, surrogates, vault, engine), `detectors/` (secrets, structured patterns, dictionary, overlap
resolution), `audit/` (hybrid ML-KEM-768+X25519 HPKE keys via `cryptography` 50, sealed envelope,
hash-chained log, dev token "1234" via Argon2id), `corpus/` (synthetic generator), `bench.py`,
`knobs.py` (ADR-0012 catalogue → `ppe explain`), `selftest.py` (`ppe verify`), `cli/`.
Findings while building: (1) phone false positives from dates/ISBNs/order numbers → context-word
setting `detection.phone_context` (optional = recall 1.000 / precision ~0.92; required = recall ~0.85 /
precision 1.000), default optional (recall first); (2) R3 needs format transfer (a surrogate is a
canonical value rendered into each occurrence's format); (3) the formatter wrote literal bidi/zero-width
characters into source → replaced by code points + Trojan Source guard test.
Next: commit; phase 2 proxy (streaming restore R5, wire formats); signed checkpoints; retention.

## Overnight pass 2026-10-02 (planning only — nothing built, run or benchmarked)

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

Nothing committed (resume-card rule). Suggested first commit when the operator approves: `docs/`
and `.gitignore` as "docs: research pass, ADR-0001..0006, threat model, controls mapping".

## First steps when resuming

1. ~~Swap/restore family~~ → ADR-0002 (proposed). ~~Retention~~ → ADR-0003. ~~Audit~~ → ADR-0004.
   Operator reviews ADR-0001…0006 and PLAN §6 items 2–12; mark ADRs accepted or amend.
2. Write `schemas/policy.schema.json` and `schemas/audit-record.schema.json` from ADR-0004/0006.
3. ~~Threat model draft~~ → `docs/threat-model.md` draft 0 (egress guard).
4. Read the still-unread sources listed in `sources/README.md` (CSA final now read; EDPB 01/2025 and
   ENISA primary text, PDPA sections, PDPC Key Concepts guidelines, SP 800-53r5 primary text).
5. Stand-alone plug-in survey: Claude Code done (`sources/claude-code-gateway.md`); still open:
   Codex CLI, Cursor (client- vs server-side base URL?), Continue, OpenAI SDK clients; other gateways.
6. Build the synthetic corpus (SG/EU/US + adversarial variants) — it gates every model choice.
7. When the GPU is free and the operator allows: bench GLiNER2-PII, OpenAI Privacy Filter, and the
   parallel-decision arbiter (fork build) per ADR-0005; then skeleton and phase 1.

## Working agreements carried over

Test before claiming; mark anything untested. No make-work for the operator: draft first, operator
corrects. Planning answers stop without offers. No real personal data anywhere in the repo (synthetic
corpus only).

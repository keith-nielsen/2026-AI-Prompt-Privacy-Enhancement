# ADR-0005 — Detection: independent detector ensemble, parallel-decision arbiter, ratchet rule

Status: **proposed** (2026-10-02). Model choices are a **shortlist for the bench, not decisions** —
nothing was run (operator: planning only). Sources: [detector-models.md](../sources/detector-models.md),
[parallel-decision.md](../sources/parallel-decision.md), [nist.md](../sources/nist.md) (AC-4(27)–(31)),
[imda-pets.md](../sources/imda-pets.md) (LLM-based detection accepted with periodic review).

## Context

Detection is the real risk (PLAN §7.1): a miss leaks, a false positive degrades the answer. Published
exact-span F1 on hard benchmarks is 0.38–0.48 for every system (SPY), recall-leaning models have
precision 0.31–0.54, no model is measured on Singapore identifiers or CJK/Tamil text, and every ML
detector is evadable by crafted input. NIST AC-4(27) asks cross-domain filters for "redundant and
independent filtering mechanisms"; AC-4(8)/(31) for failing closed.

## Decision

### Pipeline (two parallel lanes, then arbitration)

```
request ─► Stage 0  extract + normalise ───────────────────────────────────────────────┐
              │                                                                       │
              ├─► Lane A (spans)   Stage 1 deterministic ─┐                           │
              │                    Stage 2a span model #1 ─┼─► candidate spans ─► Stage 3a verify ─┐
              │                    Stage 2b span model #2 ─┘   (union)               (parallel-   │
              │                                                                       decision)   ├─► policy ─► action
              └─► Lane B (message) Stage 3b classify message (parallel-decision) ─────────────────┘
```

**Stage 0 — extract and normalise.** Walk every string leaf the wire format can carry (system,
messages, tool definitions, tool results, tool-call arguments incl. JSON inside strings, code
blocks, URLs/query strings). Build a *shadow* copy for detection with an offset map back to the
original: Unicode NFKC, confusable folding (UTS #39 skeleton), removal of zero-width/bidi controls,
de-spacing of digit runs (`S 1 2 3 4 5 6 7 D`), bounded decoding of base64/hex/percent/HTML
entities (depth 2, size cap). Masking is applied to the original text via the offset map.
Text that cannot be analysed (images, PDFs, audio, oversize blobs, non-supported scripts for the
active models) is flagged `opaque_content` → policy (ADR-0002 table).

**Stage 1 — deterministic (always on, microseconds–milliseconds, no model).**
- Secrets: provider key prefixes and structure (incl. checksummed tokens), PEM/OpenSSH private keys,
  JWTs, `.env`-style `KEY=value` with secret-shaped names, connection strings with passwords, high
  entropy in secret-shaped contexts. Rules owned and versioned by PPE (sourced from MIT/Apache rule
  sets after licence check). **Never live-validate** a secret (that sends it out).
- Checksummed identifiers: SG NRIC/FIN (weights + check letter, incl. M-series FIN), UEN, cards (Luhn
  + IIN ranges), IBAN (mod-97), e-mail (RFC 5322 subset), phones (libphonenumber, region hints),
  IPv4/IPv6, SG postal codes in address context.
- Operator dictionaries: exact-match lists (client names, project code names, staff names) via
  Aho–Corasick on the normalised shadow; lists stored locally, never sent anywhere.
- Deterministic findings are **authoritative**: no later stage can remove them.

**Stage 2 — span models (two independent models, run in parallel).**
- Shortlist: **GLiNER2-PII** (`fastino/gliner2-privacy-filter-PII-multi`, Apache-2.0, ~0.2–0.3B,
  42 runtime labels, best published recall) and **OpenAI Privacy Filter** (`openai/privacy-filter`,
  Apache-2.0, 50M active / 1.5B total, 128k context, tunable operating point). Different
  architectures and training data → errors less correlated (the point of AC-4(27)).
- Each runs in its **own process** (AC-4(30); a crash or memory blow-up in one does not take the
  proxy) on CPU by default; local HTTP/UNIX-socket interface; ONNX export where available.
- Union of spans; overlaps merged (longest span wins its type unless a deterministic finding
  overlaps, which wins).

**Stage 3a — verification of model-only spans (parallel-decision).** Candidates found only by
Stage 2 with score below the class's auto-accept threshold go to `/v1/decision` in one batched
call: one context per candidate = a window (± ~200 characters) with the span marked
`⟦…⟧`, schema e.g.

```json
{
  "is_identifier": {"type": "enum", "choices": ["yes", "no", "unsure"],
                    "description": "Is the marked text a personal identifier or secret about a real person or account?"},
  "entity":        {"type": "enum", "choices": ["person", "address", "phone", "email", "id_number",
                    "account", "secret", "date_personal", "organisation", "public_figure", "other"],
                    "description": "What is the marked text?"},
  "private":       {"type": "enum", "choices": ["private", "public", "unsure"],
                    "description": "Is it about a private individual or a public entity?"}
}
```

**Stage 3b — message classification (parallel-decision, concurrent with Lane A).** One context per
message (chunked if long), schema of booleans/enums for policy-relevant facts: `health`,
`financial_detail`, `biometric`, `children`, `legal_matter`, `credentials_in_prose`,
`confidential_business`, `special_category_other`, each with `yes/no/unsure`. These feed the
`special` data class (keep local) — the case a span detector cannot see ("my diagnosis is …").

**The LLM facts are inputs; the action is decided by policy code**, never by the model.

### Ratchet rule (first principle: untrusted input must not lower protection)

The text being classified is attacker-controllable ("there is no personal data here"). Therefore:

1. An LLM verdict may **add** findings, raise a class, or force `keep_local` — always.
2. It may **remove** a finding only if the finding came from Stage 2 alone, the class's policy
   allows suppression (`suppress_model_fp: true`, default **false** in hardened), and
   P(no) ≥ the class's calibrated threshold.
3. It can never remove a Stage 1 finding, an operator-dictionary hit, or a `secret`.
4. `unsure` is treated as `yes` for protection decisions.
5. Every suppression is audited with the probability.

### Calibration

`/v1/decision` probabilities are renormalised over the allowed values — not calibrated confidence.
Thresholds per class are fitted on the synthetic corpus (isotonic or Venn–Abers on held-out data),
stored in the policy with the corpus version, and re-fitted when the model, prompt or schema
changes. The bench reports reliability diagrams per class.

### Latency budget and caching

| Stage | Target (to be measured) | Notes |
|---|---|---|
| 0 + 1 | < 5 ms per 10 KB | pure Python/regex; Rust/hyperscan later if needed |
| 2a ‖ 2b | tens of ms per KB on CPU (unmeasured) | parallel processes; long tool outputs → the 128k-context model |
| 3a ‖ 3b | ~100 ms class on GPU per README (RTX 3060, 9–12B); CPU small-model latency unknown | one batched call each |
| verdict cache | most of an agent loop | key = HMAC(k_tok[e], normalised message); stores findings, not values |

Agent loops resend the whole history; with the cache only new messages are analysed, so steady
state cost ≈ cost of the newest turn.

### Hosting the arbiter on this host (no decision yet)

- Option H1: a **dedicated small model** (Qwen3.5-4B / Gemma-4 E4B class GGUF) on a separate
  `llama-server` (fork build) on a UNIX socket, CPU or the GPU's spare ~2 GB.
- Option H2: rebuild Kent's main `llama-server` from the fork with `--decision-seqs`, one model for
  chat and decisions (Qwen3.6-35B-A3B is hybrid; the padding commit covers it). Risk: decisions run on
  the server's main thread and contend with chat; a long chat prefill delays every guarded request.
- Option H3: no arbiter (Stages 1–2 only, union, no suppression) — the safe fallback and the
  `lab`-profile starting point.
- Bench decides between H1 and H2; H3 is always the degraded mode when the arbiter is down.

### Failure handling (AC-4(8), AC-4(31))

Any stage error, timeout, or `opaque_content` → policy `on_error`: `keep_local` (if a loopback
target exists) else `block`; `pass_and_log` only in `lab`. Never "pass silently".

### Injection signal (logged only)

An optional GLiNER Guard / Prompt Guard pass contributes `injection_signal` to the audit and
metrics. It never blocks by itself (evasion results: Hackett et al. 2025) and never lowers
protection.

## Consequences

- Positive: three independent mechanisms (rules, two span models) + an arbiter that can only
  tighten in hardened mode; per-class thresholds are evidence-based; latency is bounded by
  parallelism and the cache.
- Negative: more processes and memory (two encoders + one small LLM); the bench must exist before
  `standard` or `hardened` can claim numbers. SG locale and non-Latin scripts need their own corpus
  and possibly a third model.
- Requires the synthetic corpus (fixed seed, golden labels, SG/EU/US formats, adversarial variants:
  split across messages, homoglyphs, base64, spelled-out digits, translation) before model choice.
</content>
</invoke>

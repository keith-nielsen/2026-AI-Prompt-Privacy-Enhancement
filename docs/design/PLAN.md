# Plan — Prompt Privacy Enhancement (PPE)

GitHub: `keith-nielsen/2026-AI-Prompt-Privacy-Enhancement` · local: `~/Documents/repo/prompt-privacy-enhancement`
Status: planning (2026-10-02). Nothing built. Sources: [`../sources/`](../sources/README.md).
Overnight research pass (2026-10-02): [`../research/2026-10-02-research-report.md`](../research/2026-10-02-research-report.md);
decisions drafted as ADR-0001…0012 in this folder (status *proposed*); [threat model](../threat-model.md);
[controls mapping](../controls-mapping.md). Where this plan and an ADR differ, the ADR is newer.

## 1. What it is

A gateway-layer package that stops identifiers and secrets in prompts from leaving the platform
in clear text, while keeping answers useful and leaving an audit trail:

- **Detect** secrets and personal data in requests bound for a cloud model (and in their replies).
- **Act** per data class: log only · swap and restore (pseudonymise) · keep local (re-route) · block.
- **Swap** identifiers for conversation-scoped keyed tokens (`<PASSPORT_7f3a9c2e1b>`), restore the
  real values in the reply (text, streamed chunks, tool-call arguments).
- **Record** one audit record per masked value (token, keyed value digest, who, when, which model),
  never plaintext, so a later investigation can answer "did this passport number ever leave?".

**Framing (operator, 2026-10-02 — ADR-0012):** PPE is a practical, testable **harness**: mechanisms,
invariants, safe defaults, reference profiles as examples, an explicit trade-off for every knob
(`ppe explain`) and conformance tests adopters run on their own deployment (`ppe verify`). Adopters
make the policy decisions (roles, deadlines, retention, approvers, drills); PPE never prescribes them.

It is a **protection mechanism, not anonymisation**: masked prompts remain personal data (PDPC Guide
to Basic Anonymisation; EDPB 01/2025). The docs say so, and the deployer's provider assessment is
still required.

**Audience (operator's direction, 2026-10-02): stand-alone first.** Most users will never run Kent;
they want to screen what their prompts send to cloud providers. Every design choice is judged by the
stand-alone user first. Kent is one integration among several (assumption: *every* Kent install
enables PPE), not the reason the package exists.

Delivery shapes, in priority order (most users first):

1. **Stand-alone local proxy** — an OpenAI/Anthropic-compatible reverse proxy on `127.0.0.1`; any
   client switches by changing its base URL. Works with tools the user cannot modify (IDEs, CLIs,
   agents). Likely the largest audience.
2. **LiteLLM plugin** — `pip install prompt-privacy-enhancement[litellm]`, one callback, deployments
   tagged `local` / `cloud`. For people already running a LiteLLM gateway.
3. **Python library / SDK wrapper** — wrap an OpenAI or Anthropic client object in-process; for
   application developers.
4. **Other gateways** (Kong AI Gateway, Envoy AI Gateway, Portkey, ...) — thin adapters if their
   plugin APIs allow; not researched yet.
5. **Kent** — the LiteLLM plugin, wired by Kent's installer (section 4).

All shapes share one core engine; adapters stay thin. Proposed (ADR-0006): shapes 1 and 2 are the
**same egress-guard proxy** — stand-alone clients point at its ingress, LiteLLM points its cloud
deployments' `api_base` at its egress; the LiteLLM callback becomes advisory (keep-local routing,
identity) and never masks. ADR-0007 (operator direction: monitor approved traffic too) adds an
**observation plane**: PPE also sits on the local leg (pass-through, tapped, never modified) and
takes data-source sensors (Hermes `post_tool_call` plugin, Gent tool wrapper, SDK), so the exposure
ledger shows everything handled, not only what leaves.

Out of scope: prompt-injection defence (only a logged signal), model-side protections, the deployer's
legal assessment, confidential inference (TEE) at the provider.

## 2. Repository layout

```
prompt-privacy-enhancement/
├── README.md                  what, why, 5-minute LiteLLM quickstart, limits ("not anonymisation")
├── LICENSE                    Apache-2.0 (same as Kent)
├── NOTICE
├── SECURITY.md                private vulnerability reporting; supported versions
├── CONTRIBUTING.md            incl. "no real personal data anywhere in the repo"
├── CHANGELOG.md               keep-a-changelog; security-relevant changes flagged
├── CITATION.cff
├── TODO.md
├── pyproject.toml             src layout; extras: [litellm], [presidio], [dev]; console scripts
├── requirements/              hash-locked lock files per extra (uv / pip --require-hashes)
├── src/prompt_privacy/
│   ├── __init__.py            version, public API
│   ├── core/
│   │   ├── types.py           Finding, EntityClass, Action, Verdict, Zone
│   │   ├── policy.py          policy loading + validation (YAML → typed); entity class → action
│   │   ├── engine.py          detect → decide → transform; gateway-agnostic, sync + async
│   │   ├── tokens.py          HMAC-SHA-256 tokeniser, normalisation per type, truncation, key ids
│   │   ├── vault.py           per-request in-memory token ↔ value map (never persisted)
│   │   ├── restore.py         unmask text, tool-call JSON, streaming (chunk-boundary buffer)
│   │   ├── cache.py           verdict cache by message hash (agent loops re-send history)
│   │   └── keys.py            key loading (file / systemd credential / env), key id, rotation set
│   ├── detectors/
│   │   ├── base.py            Detector protocol; merge/overlap resolution; scores
│   │   ├── secrets.py         key/token prefixes, PEM blocks, .env lines, entropy (block class)
│   │   ├── patterns.py        checksummed IDs: NRIC/FIN, cards (Luhn), IBAN, emails, phones
│   │   ├── presidio_http.py   Presidio Analyzer over HTTP (NER: names, locations), custom recognisers
│   │   ├── span_models.py     GLiNER2-PII / OpenAI Privacy Filter workers (own processes, ADR-0005)
│   │   ├── decision.py        parallel-decision arbiter client (/v1/decision on a UNIX socket)
│   │   └── local_llm.py       (later) local model as detector, OpenAI-compatible endpoint
│   ├── recognizers/           data files: regex + context words per locale (sg/, eu/, us/, generic/)
│   ├── audit/
│   │   ├── record.py          audit record schema (versioned JSON Schema in schemas/)
│   │   ├── sinks.py           JSONL (hash-chained, append-only), syslog, callback
│   │   ├── chain.py           hash chain + optional signature; verify
│   │   └── auditd.py          separate append-only writer + C2SP signed checkpoints (ADR-0004)
│   ├── adapters/
│   │   ├── proxy/             egress guard = stand-alone proxy (ASGI), ingress + egress listeners
│   │   │                      (ADR-0006): OpenAI + Anthropic wire formats,
│   │   │                      streaming (SSE), upstream allowlist, `ppe serve`
│   │   ├── litellm/
│   │   │   ├── callback.py    advisory CustomLogger (ADR-0006): filter-deployments for keep-local,
│   │   │   │                  identity/conversation headers; never masks (masking = egress guard)
│   │   │   └── zones.py       zone from deployment model_info (privacy_zone: loopback|cloud) + checks
│   │   ├── sdk/               wrappers for OpenAI / Anthropic Python client objects; ppe.observe()
│   │   ├── hermes/            `ppe-observe` Hermes plugin (post_tool_call sensor, ADR-0007)
│   │   └── sensor/            observe-socket server + fire-and-forget client (Gent tools, others)
│   └── cli/
│       ├── scan.py            `ppe scan FILE|-` offline detection report (no network)
│       ├── keys.py            `ppe key new|rotate|id` (writes 0600 files; prints key id only)
│       ├── lookup.py          `ppe lookup --type PASSPORT --value …` → digest search (operator only,
│       │                       every use audited, rate-limited)
│       └── verify.py          `ppe audit verify` chain check
├── schemas/                   audit-record.schema.json, policy.schema.json
├── policies/
│   ├── default.yaml           conservative: secrets block, identifiers mask, special classes local
│   ├── sg-pdpa.yaml           SG identifiers (NRIC/FIN, passport, UEN, SG address, +65 phones)
│   └── eu-gdpr.yaml
├── deploy/
│   ├── litellm/               config snippets (callback, model_info zones, env)
│   ├── presidio/              analyzer container pin (digest), recogniser config, systemd example
│   └── systemd/               credential + hardening examples
├── docs/
│   ├── architecture.md        data flow, hook points, state, failure modes
│   ├── threat-model.md        assets, adversaries (provider breach, log leak, insider, prompt
│   │                          injection exfil via tool args), STRIDE table, residual risks
│   ├── token-design.md        HMAC scheme, scope, normalisation, collision math, why not FPE
│   ├── key-management.md      custody, rotation, compromise playbook, HSM/TPM option
│   ├── forensics.md           questions it answers, lookup procedure, what it cannot do
│   ├── policy-guide.md        writing a policy; data classes; keep-local vs mask
│   ├── controls-mapping.md    PDPC GenAI §8.3/§9.3–9.5, Basic Anonymisation, PETs Annex 2, CSA
│   │                          addendum, EDPB 01/2025, ENISA, OWASP LLM02 → feature + evidence
│   ├── operator-guide.md      shadow mode, tuning false positives, reading reports
│   ├── policy-template.md     deployer's written prompt-data policy (PDPC §9.4)
│   ├── integrations/kent.md   Kent layering (section 4 below, kept current)
│   ├── design/                this plan, decision records (ADR-NNNN-*.md)
│   └── sources/               source notes (+ git-ignored PDFs)
├── tests/
│   ├── unit/                  tokens, normalisation, policy, restore (incl. streaming splits)
│   ├── detectors/             per-recogniser positives/negatives
│   ├── adapters/litellm/      in-process LiteLLM proxy with fake local/cloud deployments
│   ├── adversarial/           split identifiers, unicode confusables, base64/hex, spacing, tool args,
│   │                          model echoing altered tokens
│   ├── corpus/                synthetic PII generator (fixed seed) + golden labels — no real data
│   └── perf/                  latency per KB, cache hit rate on agent-loop transcripts
├── bench/                     detection precision/recall per entity class and locale; publishes
│                              the "rate at which personal identifiers are detected" (PDPC §8.3)
└── .github/workflows/         lint, type check, tests (LiteLLM version matrix), pip-audit, SBOM,
                               secret scan, release with provenance
```

## 3. Core design

**Zones** (ADR-0001, operator decision 2026-10-02: loopback only). Zones are `loopback` and `cloud`.
`loopback` = a verified terminal inference endpoint on this host (UNIX socket or 127.0.0.0/8 / ::1,
no proxy, attested kind, peer checks L1–L3 by profile). LAN hosts are `cloud`. Untagged → `cloud`.
The engine only transforms cloud-bound requests; in the egress-guard topology (ADR-0006) everything
reaching PPE's egress is cloud-bound by construction.

**Data classes and actions** (policy, per class):

| Class | Examples | Default action |
|---|---|---|
| secret | API keys, tokens, private keys, passwords in `.env` lines | block (error to caller, audited) |
| direct identifier | name, NRIC/FIN, passport, street address, phone, email, account no. | swap + restore |
| special | health, financial account detail, biometric refs (configurable) | keep local |
| attribute | nationality, country, city, age band | pass (task often needs it) |
| injection signal | `prompt_injection_*` patterns, classifier score | log only |

**Token** (ADR-0002 has the exact construction: per-epoch random key, length-prefixed inputs, keyed
scope). `<{TYPE}_{b32(HMAC-SHA-256(k, scope ‖ type ‖ norm(value)))[:10]}>` with scope =
conversation id (fallback: request id). Same value → same token within a conversation; unrelated
across conversations; 50-bit suffix (collision chance negligible per conversation). Normalisation per
type (case, spacing, punctuation) so `S1234567D` and `s 1234567 d` match.

**Restore** (ADR-0002 invariants R1–R6; history must stay byte-stable for preserved thinking and
prompt caching). Replace tokens in reply text, tool-call arguments and streamed deltas (buffer across
chunk boundaries until a token can no longer be partial). Unknown or altered tokens are left as-is and
counted (model mangling metric).

**Audit record** (ADR-0004 supersedes: `token_digest` instead of clear tokens, per-period random
`k_aud[p]`, C2SP signed checkpoints, separate writer; ADR-0003 retention). Original sketch (no plaintext): `ts, key_id, token, value_digest = HMAC(k_audit, type ‖ norm(value)),
type, action, detector, score, caller, conversation_id, request_id, model, deployment, zone`.
`k_audit` is a separate key so tokens and digests cannot be correlated without it. Records are
hash-chained JSONL, operator-readable only; every `ppe lookup` writes its own record.

**State.** Vault per request in memory; verdict cache keyed by message hash, TTL-bound, holds
findings (offsets, types), not values beyond request life.

**Failure modes.** Detector down / timeout → policy `on_error`: `keep_local` (default for Kent),
`block`, or `pass_and_log` (lab). Never silently pass to cloud in a non-lab profile.

**Shadow mode.** Detect and audit, transform nothing; report what would have happened. First
deployment step everywhere.

## 4. Kent integration (layering) — one integration, kept thin

Kent is a consumer, not a driver: nothing Kent-specific goes into the core. If Kent needs something
the stand-alone user does not, it belongs in Kent's installer or in a generic extension point.

Principle: Kent consumes PPE as an **external, pinned dependency**; no PPE code is copied into Kent.
Kent owns the wiring (install module, config, credentials, conformance, bench); PPE owns behaviour.

| Kent piece | Change |
|---|---|
| `install/services/litellm/install.sh` | install the PPE wheel (pinned version + SHA-256 in `versions.env`) into `/opt/kent-litellm` |
| `configs/litellm_config*.yaml` | add `prompt_privacy.adapters.litellm.callback` to `callbacks` beside `kent_gateway.activity_logger`; `model_info.privacy_zone` on every deployment (`router`/`fast` loopback, `smart`/`frontier` cloud, oracle in sim = cloud). **ADR-0006:** `smart`/`frontier` `api_base` → PPE egress socket; `content_policy_fallbacks` → `fast`; `forward_client_headers_to_llm_api` for the conversation header; LiteLLM log level ≠ debug, no prompts in spend logs |
| observation (ADR-0007) | llama-server `--host` → UNIX socket in a PPE-only group; `router`/`fast` `api_base` → PPE observe; `ppe-observe` Hermes plugin for Kent; sensor client in `templates/app/gent/tools.py` + per-Gent observe socket mount; optional `data_classes:` in `project.yaml`; conformance: coverage 100 %, no direct client of the model socket |
| egress (Squid) | ADR-0001/0006: provider domains reachable only from PPE's account; LiteLLM's account loses direct egress to `api.anthropic.com` |
| credentials | `ppe_token_key`, `ppe_audit_key` as systemd credentials of `kent-litellm` (root-owned, 0600 source, `LoadCredential=`); key ids recorded in the install manifest |
| new module `install/services/presidio/` | **Registry moved** (Jun 2026): `ghcr.io/data-privacy-stack/presidio-analyzer` (MCR path frozen). ADR-0005 may replace Presidio by PPE's own rules + GLiNER2-PII/OpenAI Privacy Filter services. Presidio Analyzer container, digest-pinned, own account, `127.0.0.1:5002`, no egress, read-only, no capabilities (same pattern as SearXNG) |
| identity | PPE reads the caller from LiteLLM's `UserAPIKeyAuth` set by `kent_gateway.user_api_key_auth` (operator / kent / gent-<id>) |
| conversation id | Hermes session id passed as a header by Kent's gateway client, or set by `kent_gateway` from request metadata; ties into v0.2.0 trace correlation. Until then: request-scoped tokens |
| audit store | `/var/lib/kent-ppe/audit.jsonl` (owner `litellm`, group `kent-operators` read, append-only); never shipped to Loki; `kent ppe lookup` wraps the CLI for operators |
| metrics | counters only (findings per class, actions, detector latency, restore misses) via the existing Prometheus path; no content |
| profiles | lab: shadow → mask with `on_error: pass_and_log`; hardened: mask, `on_error: keep_local`, secrets block |
| conformance (`tests/conformance`) | callback loaded; zones complete (no untagged deployment); keys present with right owner/mode; Presidio healthy; canary: synthetic NRIC to a cloud tier in sim → oracle sees only a token, reply restored |
| bench (`tests/bench`) | synthetic-PII items: detection rate per class; Kent task quality with PPE on vs off (does masking hurt answers?); restore-miss rate |
| docs | architecture §7 gateway table, controls.md (F-08 → mitigated), privilege-map (keys, store), TODO egress-guard entry → points here |
| uninstall | remove wheel, credentials, Presidio module; audit store archived per the operator's evidence rules |

Order on the request path in Kent: `custom_auth` (identity, policy) → PPE pre-routing (detect,
cache) → router picks tier → PPE filter-deployments (keep-local classes drop cloud deployments) →
PPE deployment hook (mask if zone = cloud) → provider → PPE restore → `KentActivityLogger`
(metadata only, unchanged).

Gents are local-only and untouched; their text reaches the cloud only via Kent's escalation calls,
which pass PPE like any Kent call.

## 5. Phases

| Phase | Deliverable | Exit check |
|---|---|---|
| 0 | repo skeleton, threat model, ADRs for the three hard problems (§7), policy + audit schemas — *ADRs 0001–0006, threat model draft 0, controls mapping draft 0 written 2026-10-02* | reviewed by operator |
| 1 | core engine + secrets/pattern detectors + swap/restore + audit; CLI `scan`, `key`, `verify` — *2026-10-02: built: Stage 0 shadow, Stage 1 rules, surrogates (G1/G2/G4/token) with format transfer, restore R1–R4, sealed 2-of-2 hybrid-PQ audit log, synthetic corpus + bench, `ppe scan/mask/corpus/bench/explain/verify/audit`; 56 tests + 10 self-checks green. Not yet: streaming restore (R5), signed checkpoints, retention/shredding, per-class forms* | unit + adversarial tests pass; synthetic corpus precision/recall reported |
| 2 | stand-alone proxy (`ppe serve`, OpenAI + Anthropic formats, streaming), shadow mode = observation plane on every leg + sensor API + exposure ledger (ADR-0007) — ships **before** masking, so the baseline "what are we protecting" exists first | a real CLI/IDE client works through it unchanged |
| 3 | LiteLLM adapter (hooks above) | in-process proxy tests; hook questions in `sources/litellm-hooks.md` answered by test |
| 4 | span models (GLiNER2-PII, OpenAI Privacy Filter; Presidio optional) + parallel-decision arbiter + SG/EU recognisers; masking on (ADR-0005) | bench: detection per class ≥ target; answer-quality delta acceptable |
| 5 | keep-local action, retention enforcement, `lookup` with its own audit, forensic drill | drill documented end to end |
| 6 | public release v0.1.0: docs, controls mapping, PyPI with provenance | CI green |
| 7 | Kent wiring (installer, zones, credentials, Presidio module, conformance canary, bench) | Kent conformance 0 FAIL |
| later | SDK wrappers; other gateways; local-LLM detector; output-side PII scan; HSM/TPM keys; PET Sandbox application |

## 6. Open decisions (operator) — deferred to the start of the real work ("easy" ones)

1. ~~Default for untagged deployments~~ — **decided** 2026-10-02: cloud; local zone = loopback only
   (ADR-0001).
2. `on_error` in hardened: keep local if a loopback target exists, else block (ADR-0005 proposes
   exactly this) — confirm.
3. Which classes are "special" (keep local) by default in `sg-pdpa.yaml` — proposal: health,
   financial account detail, biometric, children, legal matter (Stage 3b fields, ADR-0005).
4. Audit retention period and rationale (PDPC §7.2–7.3) — proposal 12 months of `k_aud[p]` life
   (ADR-0003); the deployer writes the rationale.
5. Conversation-id source for Kent — proposal: Hermes session id in `x-ppe-conversation-id`,
   forwarded by LiteLLM (`forward_client_headers_to_llm_api`), trusted only from LiteLLM's peer
   credentials (ADR-0006).
6. PyPI name `prompt-privacy-enhancement`, import name `prompt_privacy`, CLI `ppe` — confirm.

New from the 2026-10-02 research pass (recommendation first):

7. **Topology**: egress guard + advisory LiteLLM callback (ADR-0006) instead of masking inside the
   deployment hook — confirm. Biggest change to this plan.
8. **Arbiter hosting** for parallel-decision: dedicated small GGUF on its own llama-server (fork) on a
   UNIX socket (recommended, isolates contention) vs Kent's main llama-server rebuilt from the fork.
   Decide after the bench.
9. `suppress_model_fp` (LLM may remove a model-only false positive): lab/standard only, never
   hardened (recommended) vs never.
10. Provider credentials: PPE passes the caller's key through (recommended for stand-alone) vs PPE
    holds provider keys and issues PPE tokens (organisations).
11. Non-Latin-script content until a measured model exists: keep local / block in hardened,
    pass-and-log in lab (recommended).
12. "Jev" in "Jev-style parallel decisions": origin/meaning, for the docs.
13. Observation plane (ADR-0007) — **decided** 2026-10-02: per-identifier digests on approved
    traffic; model calls + data sources; local side observe + alerts, never block. Still open:
    baseline multiples for the bulk-volume alert; whether Gents must declare `data_classes`.
14. Surrogates (ADR-0008) — **decided** 2026-10-02: plausible dummy data for all classes, typed tokens
    opt-in; special categories stay keep-local. Open: SG phone surrogate range (ask IMDA); default
    `min_guarantee` per profile; `announce: system_note` (bench decides).
15. Audit minimisation (ADR-0009, **revised by ADR-0010**) — **decided** 2026-10-02: *nothing* in clear;
    whole records sealed 2-of-2 (machine key + USB-token key; dev token = `"1234"`); health-only
    telemetry; opaque alerts; offline decrypter for ledger/investigations. Open: key custody for Kent
    (HSM vs smart card vs air-gapped laptop); period length (monthly vs quarterly).
16. Second-token escrow / 2-of-3 across auditors when the USB part is solved (ADR-0010); whether any
    finding counters may ever be exposed in production metrics (proposal: never).
17. Break-glass release (ADR-0011) — **decided** 2026-10-02: 2 approvers (never users of the key)
    release a time-bound, scoped session to 1 investigator (never an approver) on a decryption broker;
    keys stay in TPM/HSM; auto-close, revoke, re-arm. Open: approver roster size (≥ 3), default and
    max session length (4 h / 12 h proposed), whether the time-locked single-approver emergency path
    is enabled, broker on a separate host/VM.
18. Case-study hardening H1–H13 — **decided** 2026-10-02: all adopted as requirements of ADR-0011 (and
    H11 in ADR-0010). Parameters are **policy, not constants** (operator 2026-10-02): incident-envelope
    mode so limits never deny incident response; per-identity limits, alerts not denials in normal
    mode, hard stops only at machine speed; batchable reviews sized to load; drill ownership by
    assurance tier (external → internal audit → rotating approver); small-org compensating mode.
19. Framing (ADR-0012) — **decided** 2026-10-02: mechanism not policy; invariants vs knobs; profiles are
    examples; every knob has a trade-off statement and a proving test. Items above that read like org
    policy (deadlines, caps, owners, retention) are adopter knobs with defaults.

## 7. The hard problems (where the real work is)

The operator's view (2026-10-02): the section 6 choices are easy; the work is in (1) on-the-fly
swap/restore, (2) data retention, (3) the audit function. Notes below are starting material, not
decisions. Drafted decisions: §7.1 → [ADR-0002](ADR-0002-swap-and-restore.md), §7.2 →
[ADR-0003](ADR-0003-retention-and-keys.md), §7.3 → [ADR-0004](ADR-0004-audit-and-telemetry.md);
detection → [ADR-0005](ADR-0005-detection-ensemble.md); zones → [ADR-0001](ADR-0001-trust-zones.md);
topology → [ADR-0006](ADR-0006-interface-and-topology.md).

### 7.1 On-the-fly swap and restore ("encrypt/decrypt")

Strictly this is keyed **tokenisation / pseudonymisation**, not encryption of the payload. Three
families, each a different answer to "can anyone ever turn a token back into the value after the
request is over?":

| | A. HMAC token + per-request vault | B. Value encrypted inside the token | C. HMAC token + local encrypted escrow |
|---|---|---|---|
| Token | short, opaque (`<PASSPORT_7f3a9c2e1b>`) | long (value length + tag), e.g. AES-SIV / FF1 format-preserving | short, opaque |
| Restore needs | in-memory map for the request | only the key (stateless) | in-memory map; escrow only for later lookups |
| Later "what was token T?" | impossible (only confirm a guessed value) | anyone with the key, from any provider log | operator with the escrow key, from the local table |
| Key leak exposes | enumerable classes (NRIC, phone) by brute force | **every** token the provider holds | escrow table if also stolen; tokens alone as in A |
| PDPC fit | strict; no mapping table | key = universal mapping table | "reversible pseudonym, mapping table kept securely" (Basic Anonymisation p.36–38) |

Leaning: **A as default, C as an option** for deployers who must be able to answer "what did token T
stand for" (incident response, data-subject requests). B mainly where restore must be stateless
across processes — which a request/response proxy does not need (the same process handles both).

Sub-problems to solve and test:

- **Detection is the real risk.** A miss leaks; a false positive degrades the answer. Overlapping
  spans, multiple detectors, confidence thresholds per class, locale (SG/EU/US) recognisers.
- **Normalisation** per type (case, spaces, dashes) so the same value always gives the same token;
  versioned, because audit lookups depend on it.
- **Where text hides:** system prompts, tool definitions, tool results, JSON in strings, code blocks,
  URLs, base64/data URIs, file attachments, images (v1: detect what it can and apply policy — block
  or keep local; no OCR).
- **Token survival through the model:** models change case, drop brackets, translate the label,
  split or pluralise tokens, invent new ones. Restore must tolerate small mangling with strict
  bounds, never guess, and count misses (metric).
- **Streaming:** SSE deltas can split a token across chunks → buffer until no partial token can
  remain; same for tool-call argument deltas; keep JSON valid (escape restored values).
- **Conversation scope without a conversation id:** stand-alone clients send no id. Idea to validate:
  scope = HMAC of a conversation fingerprint (system prompt + first user message), which chat clients
  resend every turn; fallback request id. Stable scope also keeps provider prompt caching working.
- **Tasks that need the literal value** ("format my passport number", "spell my name backwards"):
  break under masking. Options: per-request opt-out header (audited), or class-level keep-local.
- **Endpoints that cannot be restored:** embeddings (masking changes vectors), moderation, batch/file
  uploads → policy per endpoint (mask-only, keep-local, block).
- **The proxy is a honeypot:** it sees all plaintext. Local only, minimal dependencies, no telemetry,
  no plaintext in its own logs (and check upstream libraries: LiteLLM verbose logs, spend logs with
  stored prompts, observability callbacks may capture pre- or post-mask payloads depending on order).

### 7.2 Data retention

What exists and for how long:

| Data | Where | Default lifetime |
|---|---|---|
| plaintext ↔ token map | process memory | request (zeroise after restore) |
| verdict cache | memory | TTL; findings (offsets, types), no values |
| audit records (digests) | local store | policy period, with written rationale (PDPC §7.2–7.3) |
| escrow (option C) | local encrypted table | shortest workable; separate key |
| shadow reports | local | short |
| prompts at the provider | provider | outside our control — document, point to provider terms |

Ideas to work through:

- **Crypto-shredding for audit retention:** digest key rotated per period (e.g. monthly); deleting a
  period key ends linkability for that period without rewriting the hash-chained log. Reconciles
  "append-only, tamper-evident" (CSA) with "remove the means of association" (PDPC s.25).
- Retention enforced by the tool (a `ppe retention run` job), not by convention.
- Data-subject access (PDPC Part IV, GDPR art. 15): a digest lookup can say *that* and *when* a
  person's identifier went to which provider; it cannot produce content (none stored). Document.
- Breach scenarios per Basic Anonymisation p.31–32 → incident playbook (key leak, store leak, both).

### 7.3 The audit function

Questions it must answer: did value V ever leave, when, from whom, to which model? Which classes leave
most? Was anything blocked or kept local? Was a policy bypassed (opt-out header)? Is the log intact?
(With option C: what did token T stand for?)

- **Integrity:** hash chain; periodic signed checkpoints; optional external anchor. Writer can append,
  not rewrite (separate writer process or OS append-only attribute).
- **The audit is itself personal data** (pseudonymised): restricted access, every lookup audited and
  rate-limited (EDPB 01/2025), per-period keys (above).
- **Volume:** agent loops resend the history; record a finding once per (scope, token), not per
  request, or the log explodes.
- **Reproducible lookups:** record normaliser version and key id with each record.
- **Export:** JSONL + JSON Schema + verifier; optional SIEM mapping (metadata only) since CSA expects
  gateway logs in a SIEM.
- **Reports:** shadow-mode "what would have been masked"; detection metrics on the synthetic corpus
  (PDPC §8.3 metric); restore-miss rate.

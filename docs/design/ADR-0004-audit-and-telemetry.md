# ADR-0004 — Audit trail, telemetry, real-time alerting and after-the-fact reporting

Status: **proposed** (2026-10-02). Resolves PLAN §7.3 and RESUME step 2 (audit model). **Amended by
ADR-0009**: each record = clear *occurrence* part (incl. `count` and `access_principal`) + *sealed*
part (all value-derived digests, HPKE to an offline period key). `ppe lookup` becomes the offline
investigation procedure. Integrity, telemetry and alerts below are unchanged.
Sources: [csa-agentic-addendum.md](../sources/csa-agentic-addendum.md) (final: tamper-evident,
signed logs, SIEM), [nist.md](../sources/nist.md) (AU-2/3/6/9/10/11/12, SP 800-92r1 draft),
[eu-edpb-enisa.md](../sources/eu-edpb-enisa.md) (logs as a privacy risk; log reverse application),
[litellm-2026.md](../sources/litellm-2026.md) (guardrail log leak), OpenTelemetry GenAI conventions
(content capture is opt-in; conventions still "Development", no release as of Aug 2026).

> **Superseded in part by [ADR-0010](ADR-0010-fully-sealed-audit.md) (2026-10-02):** records are envelopes around fully encrypted content; Prometheus is health-only (no class/caller/zone labels); alerts are opaque (`ppe_alerts_total{severity}` + sealed detail); the SIEM gets envelopes, opaque alerts and health; reports come only from the audit decrypter.

## Context

Two demands pull against each other: CSA wants "immutable, tamper-evident audit logs that capture
prompts, responses, and tool invocations"; EDPB warns that logs of user inputs are a breach target.
Resolution: the audit captures **what happened to each identifier** (token, keyed digests, action,
who, where) and never the plaintext. Three separate channels with different rules:

| Channel | Content | Audience | Integrity |
|---|---|---|---|
| **Audit** | one record per (scope, token, action) + policy/key/lookup events | operator group only | hash chain + signed checkpoints |
| **Telemetry** | counters, histograms, spans with no content | ops dashboards, SIEM | backend's |
| **Reports** | aggregates; shadow-mode "would have" summaries | operator, deployer, auditors | generated from audit |

## Decision

### Audit record (JSON, schema `schemas/audit-record.schema.json`, `"v": 1`)

```
ts             RFC 3339 UTC, ms
seq            monotonically increasing per log
prev           SHA-256 of the previous record's canonical bytes (RFC 8785 JCS)
event          mask | block | keep_local | pass_logged | restore_miss | opt_out | detector_error |
               observe | sensor_gap |
               policy_loaded | key_rotated | key_destroyed | lookup | retention_run | start | stop
flow, source   observation plane only (ADR-0007): source | prompt | reply_generated | reply_echo;
               source kind/name/host_or_area/locator_digest
req_id, conv   request id; conversation scope id (already keyed, ADR-0002)
caller         caller identity (gateway identity or client token id), never a raw API key
zone, model, deployment, endpoint
class, type    data class and entity type
token_digest   HMAC(k_aud[p], token)            — find the conversation from a provider-side leak
value_digest   HMAC(k_aud[p], type ‖ norm_v(value))   — "did V ever leave?"
norm_v         normaliser version
detectors      [{id, version, score}] that produced/confirmed the finding; arbiter verdict + probability
policy_hash    SHA-256 of the active policy file
key_ids        {tok, aud}
```

- **Deduplicate**: one `mask` record per (scope, token, zone) per epoch, not per request — agent loops
  resend the whole history every turn; a per-request record would explode volume and add nothing.
  Per-request activity goes to telemetry counters.
- Never in a record: values, tokens in clear, raw texts or excerpts, raw API keys, raw session ids.

### Integrity

- v1: **hash chain** (above) + **signed checkpoint** every N records or T minutes in the C2SP
  `tlog-checkpoint` signed-note format (origin, size, root/head hash; Ed25519 `k_sign`) — the same
  format Go's checksum DB, Sigstore Rekor and static CT logs use, so standard verifiers apply.
- v2 (later): Merkle tree (RFC 9162 / C2SP tlog-tiles) for inclusion and consistency proofs;
  optional external witness co-signing (C2SP tlog-witness) or anchoring checkpoints off-host.
- Writer: a separate `ppe-auditd` process and account receives records over a UNIX socket
  (`SO_PEERCRED`-checked), appends to a file with the `chattr +a` attribute, fsyncs, signs
  checkpoints. The proxy can append via the socket but cannot rewrite, truncate, or sign
  (AU-9, SC-39). On writer failure the proxy fails closed (`audit_unavailable` → `on_error`).
- `ppe audit verify` recomputes the chain, checks every checkpoint signature, and reports gaps.

### Access (AU-9(4); EDPB "reverse application")

- Files `0640 ppe-auditd:ppe-operators`; never shipped to Loki or any shared log backend.
- `ppe lookup --type NRIC --value …` (or `--token <PASSPORT_…>`): operator group only; reads
  the value from a TTY prompt (not argv — avoids shell history and `/proc/*/cmdline`); computes
  digests for each live period; rate-limited (default 20/hour per operator); **writes its own audit
  record** (`event: lookup`, operator, type, result count — not the value).

### Telemetry (real time)

- **Prometheus** counters/histograms, no content, bounded label sets (class, type, action, zone,
  model, detector, outcome) — never tokens, digests, callers' free-form ids:
  `ppe_findings_total`, `ppe_actions_total`, `ppe_blocks_total`, `ppe_restore_miss_total`,
  `ppe_detector_latency_seconds`, `ppe_detector_errors_total`, `ppe_verdict_cache_hits_total`,
  `ppe_on_error_total`, `ppe_audit_write_failures_total`, `ppe_zone_verification_failures_total`.
- **OpenTelemetry** spans optional, following GenAI semantic conventions with content capture
  **off** (`gen_ai.*` operation/model/usage attributes only); PPE never emits
  `gen_ai.client.inference.operation.details` content events.
- **SIEM**: RFC 5424 syslog or JSONL export of a metadata-only projection (event, class, action, zone,
  model, caller, req_id, ts) — CSA's "streamed into a SIEM" without personal data.
- **Alerts** (shipped as Prometheus rules): any `block` of class `secret`; detector down / on_error
  firing; restore-miss rate above baseline (model mangling or an attack on tokens); zone
  verification failure; audit writer failure; any `lookup`; `opt_out` use; policy change.

### Reports (after the fact)

- `ppe report --since … --until …`: per class/type/action/model/caller counts, blocks, keep-local
  routes, opt-outs, restore-miss rate, detector agreement matrix (how often each detector alone
  found something → measures the ensemble's value), lookups performed.
- **Exposure ledger** (ADR-0007): distinct identifiers handled per class, by zone, caller and source,
  with the protection outcome for cloud-bound ones and the coverage figure next to every count.
- **Shadow mode** report (= enforcement plane in observation mode, ADR-0007): what *would* have been masked/blocked, with `<TYPE>`-redacted excerpts
  (± 20 characters, identifiers inside also redacted) for false-positive tuning; 30-day retention.
- **Bench report** (from `bench/`): detection precision/recall per entity class and locale on the
  synthetic corpus — the PDPC §8.3 "rate at which personal identifiers are detected and redacted"
  and the NIST AI 600-1 MEASURE 2.10 evidence. Published with each release.

### Upstream log hygiene (checked by `ppe doctor` / Kent conformance)

- LiteLLM not at debug log level (`verbose_logger.debug("Guardrail response: …")` would log texts).
- LiteLLM `store_prompts_in_spend_logs` off; observability callbacks (Langfuse etc.) either off or
  placed so they see only masked payloads — in the egress-guard topology (ADR-0006) LiteLLM sees
  plaintext, so its callbacks must be local-only or disabled.
- llama-server (detector) at low verbosity; Presidio/GLiNER services without request logging.
- PPE hook return values are minimal objects (lesson of LiteLLM's 2026-03-18 incident).

## Consequences

- Positive: answers the forensic questions (PLAN §7.3) without becoming a store of personal data;
  integrity is verifiable with standard tooling; SIEM gets what it needs.
- Negative: dedup means "how many times did V leave" is approximate (per scope, not per request);
  per-request counts exist only as aggregates. Two extra processes (auditd, optional escrow).
</content>
</invoke>

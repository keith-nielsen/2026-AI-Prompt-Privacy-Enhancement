# ADR-0012 — Mechanism, not policy: a right-sizable, testable harness with explicit trade-offs

Status: **proposed** (2026-10-02). Operator direction (2026-10-02): "I don't want to focus too much on
exact corporate policy for a target entity, those will be decisions that THEY make … I want us to
have this as a practical and testable harness that people can use and base their own security
tools, policies, and procedures that is right-sized to exactly their needs — and clearly understand
the tradeoffs they make while doing it." **Governs how every other ADR is read.**

## Decision

### 1. What PPE ships, and what adopters decide

| PPE ships | Adopters decide |
|---|---|
| mechanisms (zones, swap/restore, detectors, observation, sealed audit, break-glass broker, shredding) | which mechanisms to turn on |
| **invariants** that can't be configured away (§2) | every parameter in the catalogue (§3) |
| safe defaults + **reference profiles** as worked examples (§4) | their own profile, roles, approvers, deadlines, retention, drill ownership, escalation paths |
| a **trade-off statement** for every knob | whether the trade-off is acceptable for them |
| **conformance tests** proving each mechanism works as configured (§5) | their procedures around the tool |
| measured detection rates (bench) | the residual risk they accept |

Numbers that appear in ADRs (24 h windows, 30-day epochs, 12-month retention, ≥ 3 approvers, …)
are **defaults or examples**, never requirements, unless they're listed as invariants.

### 2. Invariants (not configurable, because breaking them would make the tool's records or claims untrue)

1. PPE never persists or emits plaintext protected values (audit, metrics, logs, errors, headers).
2. Untagged or unverifiable endpoints are `cloud`.
3. Secrets are never live-validated against their issuer.
4. Restore is closed-world (only values issued in this request's vault).
5. In break-glass, no person is ever handed a decryption key; capability only.
6. Dev keys (e.g. the `"1234"` token stand-in) are refused outside the `lab` profile, and records
   written under them are marked as such.
7. The audit integrity chain is always on.
8. Any relaxed safety setting (e.g. `on_error: pass_and_log`) is only available in `lab`, and every
   record written under it carries the profile.

### 3. Knob catalogue (each: options · default · you gain · you give up · proving test)

| Area | Knob | Options | Default | Gain | Give up | Test |
|---|---|---|---|---|---|---|
| Zones (0001) | `local_assurance` | L1 / L2 / L3 | L2 | stronger proof the "local" model is local | portability (L2/L3 Linux-only), setup | zone-spoofing suite |
| Topology (0006) | `topology` | egress guard / in-process LiteLLM callback | egress guard | non-bypassable with egress control; version-independent | extra hop; wire-format work | bypass test, `ppe doctor` |
| Swap (0002/0008) | `form` per class | surrogate / token / keep_local / block / pass | surrogate (identifiers), keep_local (special), block (secret) | natural model behaviour (surrogate); safety (token/block) | restore complexity, fake-name collision (surrogate); utility (block) | restore property tests R1–R6 |
| | `min_guarantee` | G1 / G2 / G3 / G4 | G4 (identifiers G2 in high-assurance example) | provably-not-real surrogates | more classes fall back to tokens | surrogate validity tests |
| Detection (0005) | `depth` | rules / + span models / + arbiter | + arbiter if available, else + span models | recall, special-category detection | CPU/GPU, latency, more moving parts | bench per class |
| | `suppress_model_fp` | off / on | off | fewer false positives | arbiter-steerable misses | injection-against-arbiter suite |
| Failure (0005) | `on_error` | keep_local / block / pass_and_log (lab) | keep_local, else block | no silent leaks | availability during detector outages | fault injection |
| | `opaque_content` | keep_local / block / pass_and_log (lab) | keep_local, else block | images/PDFs never leave unseen | can't use cloud for attachments | attachment tests |
| Observation (0007) | `observe` | off / model legs / + data sources | model legs | visibility of what is protected | load, more sensors, audit footprint | coverage test |
| | `observe_granularity` | counts / digests | digests (sealed) | per-identifier investigations | larger (sealed) record set | lineage test |
| Audit (0009/0010) | `audit_protection` | plain (lab) / sealed digests / fully sealed 2-of-2 | fully sealed | no breadcrumbs for attackers | no attribution dashboards; triage needs the decrypter | breadcrumb red-team test, theft test |
| | `second_part` | passphrase / file / USB token / HSM | passphrase (single user), token (team) | key off the host | operational custody; loss = audit loss | decrypt-with-one-part-fails test |
| | `pq_wraps` | hybrid / classical | hybrid | harvest-now-decrypt-later resistance | larger records, draft-standard libs | known-answer tests |
| Telemetry (0010) | `metrics_exposure` | health / + aggregate counts / + attributed (lab) | health | nothing for an attacker to target | no live attribution | label-audit test |
| | `client_detail` | opaque ref / class names (lab) | opaque ref | no leakage via client logs | less self-explaining errors | error-format test |
| Retention (0003/0010) | `period`, `retention`, `shred` | durations; on/off | monthly, 12 months, on | linkability ends; quantum exposure shrinks | late investigations impossible after shredding | retention-run test |
| Keys (0003) | `custody` | file / systemd-creds+TPM / HSM | systemd-creds+TPM where present | keys off disk / unexportable | setup, hardware dependency | key-permission checks |
| Break-glass (0011) | `release_mode` | off (offline decrypter only) / 1 approver + time-lock / k-of-n | off (single user), 2-of-n (team) | live review when needed | concentrated risk while sessions run | full H1–H13 suite |
| | `session_ttl`, `idle_close` | durations | 4 h / 15 min | bounded exposure | re-approval friction | expiry tests |
| | `incident_envelopes` | off / on | on where release_mode ≥ 2-of-n | no self-inflicted denial during bursts | broader pre-approved scope during an incident | burst test |
| | `velocity` | alert-only / deny thresholds; machine-speed ceiling | alert-only + ceiling | resists AI-speed abuse without denying humans | relies on review for human-speed abuse | rate tests |
| | `review` | individual / batch, deadlines | batch for live view-only, individual for export/historical | right-sized review effort | slower detection of misuse in batches | review-debt tests |
| | `drill_cadence`, `drill_owner` | any | quarterly; adopter names owner | confidence the break-glass works | effort | drill script + sealed report |
| Scope (0002) | `conversation_key` | header / chain / fingerprint / request | first available | stable surrogates, cache, thinking | — | determinism tests |

### 4. Reference profiles (worked examples, not prescriptions)

| Profile | For | Highlights |
|---|---|---|
| `lab` | development, demos | relaxed failure settings allowed, dev keys (`"1234"`), attributed metrics, everything marked lab |
| `personal` | one person, stand-alone proxy, laptop | L1/L2, surrogates, rules + one span model, observation of model legs, fully sealed audit with **passphrase** second part, break-glass **off** (offline decrypter only) |
| `team` | small team / Kent-like single host | L2, egress guard + LiteLLM, full ensemble, observation incl. data sources, USB-token second part, 2-of-n break-glass with incident envelopes |
| `regulated` | organisations under PDPA/GDPR/sector rules | L3, `min_guarantee: G2` for identifiers, HSM or TPM custody, shorter retention with written rationale, individual review for exports |
| `high-assurance` | critical / classified-adjacent | everything strictest; `form: token` or keep_local for names; separate broker host; external drill review |

### 5. Testability: proving your configuration

- `ppe explain` — reads the active configuration and prints, per knob, the chosen value, **what it
  protects, what it gives up, and which residual risks remain**. Adopters attach it to their own
  risk acceptance.
- `ppe verify` — runs the conformance tests that apply to the active configuration against the live
  deployment (synthetic data only): zone spoofing, bypass, restore properties, breadcrumb check,
  audit theft, one-part decrypt fails, break-glass suite, retention run. Output is a signed,
  sealed report.
- `bench/` — per-class detection rates on the synthetic corpus; adopters can add their own
  synthetic formats and re-run.
- Every ADR states its knobs and tests; a knob without a test isn't done.

## Consequences

- Positive: the project stays a harness people can right-size and audit for themselves; trade-offs
  are explicit and machine-reportable; claims are backed by tests the adopter runs.
- Negative: more configuration surface to test (a test matrix over profiles, not all combinations);
  documentation must keep trade-off statements current with every change.
- ADR-0011's operational section and any other place where a number reads like a mandate is to be
  read through this ADR: those are defaults and examples.
</content>
</invoke>

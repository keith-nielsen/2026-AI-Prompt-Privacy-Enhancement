# Research report — the interface between prompt entry and the LLM router (2026-10-02, overnight)

Prepared for the operator. **Planning only**: nothing was built, installed, run or benchmarked;
Kent's llama-server (overnight test) and LiteLLM were not touched. Facts come from documents, model
cards and code read on this date; each is traceable through `docs/sources/`. Decisions are drafted as
ADRs with status *proposed*.

Operator's direction for this pass: local zone = **loopback only**; added baseline = **NIST / US
federal**; "parallel decision mode" = `thecodacus/llama.cpp@parallel-decision`; deliverable = docs.

## 1. Answer in one paragraph

Treat PPE as a **cross-domain guard** on the one path out of the host, not as a plugin inside the
router. All cloud-bound traffic — from stand-alone clients and from LiteLLM's cloud deployments —
crosses one small PPE egress proxy that detects, pseudonymises with keyed per-conversation tokens,
forwards, and restores; host egress rules make it the only process that can reach provider APIs.
"Local" means a verified loopback endpoint (address, no proxy, attested terminal server, peer-process
checks), never just a tag. Detection is an ensemble of independent mechanisms — deterministic rules,
two span models (GLiNER2-PII and OpenAI Privacy Filter shortlisted), and a parallel-decision LLM
arbiter that verifies candidates and classifies sensitive topics but may only *tighten* protection.
The audit records what happened to every identifier using keyed digests, hash-chained with signed
checkpoints, and retention is enforced by deleting per-period keys (crypto-shredding).

## 2. First principles drawn from high-assurance sectors

| Sector practice | Principle | Where it lands |
|---|---|---|
| Military cross-domain solutions (guards; NIST AC-4(3)–(32)) | reference monitor: Non-bypassable, Evaluable, Always invoked, Tamper-proof; redundant independent filters; fail closed | egress-guard topology (ADR-0006), ensemble (ADR-0005), `on_error` |
| Military / classified networks | the host is the boundary; labels are verified, not asserted | loopback-only zone with peer verification (ADR-0001) |
| Banking / payments tokenisation (PCI DSS model) | tokens carry no exploitable value; the detokenisation capability is segregated, minimal, audited | HMAC tokens, request-scoped vault, escrow off by default (ADR-0002) |
| Crypto / key custody | separation of duties; keys never with the component that could misuse them; cryptoperiods; destruction is a control | key hierarchy, custody tiers, crypto-shredding (ADR-0003) |
| Medical de-identification | minimum necessary; de-identified ≠ anonymous; enumerate identifier types and test coverage | data classes; "not anonymisation" statement; per-class bench |
| Banking / audit | four-eyes on sensitive lookups; tamper-evident books; evidence survives the people | self-audited, rate-limited lookups; signed checkpoints (ADR-0004) |
| Sciences | reproducibility and measured error rates | versioned normalisers and rules, synthetic corpus with fixed seed, published precision/recall |
| Security engineering generally | untrusted input never lowers protection | ratchet rule for the LLM arbiter (ADR-0005) |

## 3. Findings by the dimensions the operator named

### 3.1 Boundaries — ADR-0001, ADR-0006

- *Loopback is not local.* `127.0.0.1:4000` on Kent is LiteLLM, which forwards to Anthropic; a
  local PasteGuard or Kiji would be the same. Local = a terminal inference process on this host,
  verified at levels L1 (address, no proxy, attestation) → L2 (peer process via `SO_PEERCRED` /
  `/proc`) → L3 (peer has no egress: systemd `IPAddressDeny` / netns).
- Hostname rules: only IP literals and an internally-mapped `localhost`; the IETF
  "let localhost be localhost" draft never became an RFC.
- llama-server listens on UNIX sockets (`--host x.sock`), which gives filesystem permissions and
  peer credentials — prefer them to TCP loopback.
- PPE's own listener: UNIX socket or `127.0.0.1` only, client token, `Host` allowlist, `Origin`
  rejection (DNS rebinding — Ollama CVE-2024-28224 class). Prior-art quick-starts publish on all
  interfaces (`-p 3000:3000`).
- Placement: in-process LiteLLM hooks are bypassable and version-fragile (LiteLLM's streaming
  guardrail model changed again in v1.102.0, 22 Sep 2026; 2026 brought a supply-chain compromise and
  several CVEs). An egress guard knows the target structurally and can be made non-bypassable
  with host egress rules.

### 3.2 Presentation — ADR-0006

Invisible on success (counts-only `x-ppe-*` headers); blocks return the client's own error format
naming class, reason and audit id, never the value; `ppe scan`, `ppe tail`, `ppe report`; no web UI
in v1.

### 3.3 Configuration — ADR-0006

One schema-validated YAML policy with profiles (lab / standard / hardened / paranoid), zones,
classes → actions, detector endpoints, scope sources, audit and retention. Policy hash audited on
load. Secrets only via systemd credentials or `0600` files.

### 3.4 Tracking (conversation scope) — ADR-0002

Claude Code sends `x-claude-code-session-id` on every request — a stable conversation key for the
most demanding stand-alone client. Fallbacks: integrator header, Responses API chain, fingerprint of
system + first user message, request id.

### 3.5 Encrypt/decrypt (swap and restore) — ADR-0002

- Default family A (HMAC token + request-scoped vault), option C (encrypted escrow), FF1 only per
  class (SP 800-38G Rev. 1 still a draft; FF3/FF3-1 removed), realistic fakes rejected (agents can
  act on them).
- **New hard requirement found:** history must be byte-stable across turns. Anthropic's preserved
  thinking rejects requests whose earlier `system`/`tools`/`messages` differ ("bound to a different
  conversation"), and prompt caching misses on any change. Claude Code's gateway guide warns that
  gateways which "rewrite or redact request bodies" break features. Hence: change string leaves only,
  never structure; never touch thinking blocks or signatures; assistant history is inverse-mapped,
  not re-detected; and the property `mask(restore(x)) == x` is a test family (R3).
- Token = `<TYPE_` + 10 base32 chars of HMAC-SHA-256 over length-prefixed (scope, type, normalised
  value) `>`; 50-bit suffix; collision ≈ 4.4 × 10⁻⁸ for 10,000 values in one conversation; detected
  and extended if it happens.

### 3.6 Telemetry — ADR-0004

Prometheus counters with bounded labels; OpenTelemetry GenAI spans with content capture off (the
GenAI conventions are still "Development", no release as of Aug 2026); SIEM gets a metadata-only
projection. LiteLLM must not run at debug level (its guardrail path logs guardrail responses) — and
its 2026-03-18 incident showed guardrail return values reaching spend logs and OTel traces.

### 3.7 Audit, real time and after the fact — ADR-0003, ADR-0004

Per-(scope, token) records with `token_digest` and `value_digest` under a monthly random `k_aud[p]`;
RFC 8785 canonical JSON, hash chain, Ed25519 checkpoints in C2SP `tlog-checkpoint` format; separate
append-only writer; self-audited, rate-limited lookups; alerts on blocks, detector failures,
restore-miss spikes, zone failures, lookups. Retention: delete `k_aud[p]` → the period becomes
unlinkable while chain integrity and aggregates survive.

### 3.8 Choosing BERT-class and LLM models — ADR-0005, sources/detector-models.md

| Role | Shortlist | Why | Caution |
|---|---|---|---|
| span model #1 | **GLiNER2-PII** (fastino, Apache-2.0, ~0.2–0.3B, 42 runtime labels, 7 EU languages) | best published recall/F1 on SPY (0.718 / 0.477) | no Asian languages |
| span model #2 | **OpenAI Privacy Filter** (Apache-2.0, 1.5B / 50M active, 128k ctx) | independent architecture; long inputs; tunable operating point | precision 0.31–0.54; collapses on non-Latin scripts |
| alternative | NVIDIA gliner-PII (570M) | strong, 55+ PII/PHI types | NVIDIA Open Model License — legal review |
| excluded | piiranha | — | CC-BY-NC-ND |
| injection signal (log only) | GLiNER Guard Omni / Prompt Guard 2 | cheap single pass | evadable (Hackett et al. 2025: up to 100%) |
| arbiter LLM | small instruct GGUF (Qwen3.5-4B, Gemma-4 E4B/12B) on the fork | parallel-decision batching | probabilities renormalised; injectable context |
| rules | own versioned rules from MIT/Apache sources; Presidio patterns as reference | deterministic, checksum-validated | never live-validate secrets |

Gaps: **no model is measured on Singapore identifiers or CJK/Tamil text** → deterministic SG
patterns + policy fallback for unsupported scripts until a corpus and model exist. Presidio moved to
`data-privacy-stack` (Jun 2026); Kent's Presidio module must use the new registry.

### 3.9 Parallel-decision ("Jev-style") — sources/parallel-decision.md

A good fit as the **arbiter**, not as a detector: it answers up to 32 finite fields for up to 256
contexts in one batched pass from a cached prefix (~100 ms on an RTX 3060 for 9–12B models, per the
README), with per-value probabilities and schema-valid output. Use it to (a) verify model-only span
candidates and (b) classify messages for special categories. Constraints: it cannot extract spans;
probabilities are relative to the allowed choices; the classified text can carry instructions
(→ ratchet rule); decisions run on llama-server's main thread (→ dedicated instance preferred);
the fork is 3 commits from one author and 292 behind upstream (→ pin, merge security fixes).

## 4. Changes to the plan

1. **Topology**: egress guard (ADR-0006) replaces masking inside `async_pre_call_deployment_hook`;
   the LiteLLM callback becomes advisory (keep-local routing, identity). PLAN delivery shapes 1 and 2
   share one component.
2. **Zones**: `loopback | cloud` (was `local | cloud`); untagged = cloud (PLAN §6.1 closed).
3. **Restore**: byte-stable history and R1–R6 invariants are now requirements.
4. **Keys**: independent random period keys (derivation would defeat shredding); proxy holds only the
   current audit key.
5. **Detection**: ensemble + arbiter + ratchet; shortlist above; bench before any model claim.
6. **Kent**: Presidio registry moved; LiteLLM cloud deployments' `api_base` → PPE egress; Squid ACL
   so only PPE reaches Anthropic; LiteLLM log level and spend-log prompt storage checked by
   conformance.

## 5. Decisions the operator still owns

Listed with a recommendation in [PLAN.md §6](../design/PLAN.md#6-open-decisions-operator). New ones
from this pass: confirm the egress-guard topology; arbiter hosting (dedicated small model vs Kent's
main llama-server); whether `suppress_model_fp` is ever allowed outside lab; the meaning/origin of
"Jev"; whether PPE should hold provider keys or pass them through.

## 6. What this pass did not do

- No benchmark, no model run, no build of the fork (operator instruction; GPU busy).
- Primary text of SP 800-53r5 not re-read line by line; EDPB 01/2025 final text and ENISA primary
  text still unread (summaries only); PDPA sections quoted from secondary sources.
- Cursor's base-URL behaviour (client vs server side) not confirmed.
- LiteLLM `content_policy_fallbacks` path from a PPE error not tested (code read only).

## 6a. Addendum — observation plane (operator review, same day)

The operator pointed out that an egress-only filter can't see what the local model consumes, and
that knowing how much sensitive data is handled *inside* the approved area is what shows the
protection's benefit and what is actually being protected. Agreed and adopted as
[ADR-0007](../design/ADR-0007-observation-plane.md):

- **Two planes, one engine**: enforcement inline on the cloud leg; observation asynchronous on every
  leg (local model calls, stand-alone ingress, replies) and at data-source entry points (Kent's Hermes
  `post_tool_call` plugin hook, read in `/opt/kent-hermes/src`; Kent's Gent `tools.py`; an SDK call).
- **Never modifies or blocks local traffic**; alerts on bulk volume, secrets in local flows, new
  sensitive sources, declared-vs-observed purpose per Gent, and coverage gaps.
- **Per-identifier keyed digests** on all observed traffic → inventory (NIST PM-5(1)), location
  (CM-12), and lineage source → loopback → cloud (CM-13) from the same audit records.
- **Exposure ledger**: distinct identifiers per class by zone/caller/source and the protection outcome
  of cloud-bound ones, always printed with a coverage figure.
- The local model server moves to a PPE-only UNIX socket, which also makes the loopback check
  stronger and turns any bypass into an alert.
- Observation (shadow mode) ships before masking, so the baseline exists before enforcement.

## 6b. Addendum — surrogate values and a minimised audit (operator review, same day)

- **Swap form** ([ADR-0008](../design/ADR-0008-surrogate-values.md)): plausible dummy data by default,
  typed tokens opt-in. Never real where that can be guaranteed: reserved ranges (RFC 2606/6761
  domains, RFC 5737/3849 IPs, NANP 555-01xx, Ofcom drama ranges, ACMA's list), or a deliberately
  invalid check character (NRIC/FIN, UEN, IBAN, Luhn). No reserved Singapore phone or NRIC range was
  found → G2 for NRIC; SG phones open (ask IMDA). Names and addresses can coincide with real people
  (documented residual). Deterministic per conversation; restore handles reformatting and name
  components; tool-call arguments are restored before execution.
- **Audit** ([ADR-0009](../design/ADR-0009-audit-minimisation-and-sealing.md)): clear *occurrence*
  records (who, which access principal, class, count, source, zone, action) drive monitoring,
  alerts and the exposure ledger (HyperLogLog distinct counts). Every value-derived field is
  HPKE-sealed (RFC 9180) to an offline per-period key, so the host can write but never read them.
  Investigations are an offline two-person procedure; destroying the private key shreds the period
  everywhere, backups included.

## 6c. Addendum — no readable breadcrumbs (operator review, same day)

The operator rejected clear occurrence records: who/which credential/what class/how much is
targeting information for an attacker. [ADR-0010](../design/ADR-0010-fully-sealed-audit.md): every
audit record is an envelope (sequence, chain hash, key ids) around AES-256-GCM content whose data key
is split 2-of-2 — one share HPKE-wrapped to the machine key (TPM-sealed, readable only by the
decrypter unit), one to the token key (USB in future; development simulates it as `"1234"` via
Argon2id, refused outside dev). Records are size-padded; telemetry is health-only; alerts and errors
carry only opaque ids; SIEM gets envelopes. The exposure ledger and every investigation come from
the audit-grade decrypter, whose own use is sealed and recorded.

## 6d. Addendum — break-glass for live review (operator review, same day)

[ADR-0011](../design/ADR-0011-break-glass-release.md): a security operator can decrypt on the fly
through a decryption broker, but only inside a release. Two enrolled approvers sign one exact
request (investigator, reason, scope, duration, period key ids, a one-shot TPM nonce). The TPM's
policy (PolicySigned ×2, PolicyOR over approver pairs, PolicyNV one-shot, expiry) authorises
the unwraps inside hardware. The investigator gets a session bound to their own hardware key —
live tail, queries, a session-bound monitoring datasource — never a key. Close (done, expiry, idle,
authenticator removed, veto) flushes the TPM session, zeroes memory, revokes the credential and
re-arms. Live-only releases use an ephemeral in-TPM key, so they never unlock history. The design
principle: release a capability, never a key, because a key can't be revoked once received.

## 7. Sources

Primary notes: [`../sources/README.md`](../sources/README.md). Web sources used in this pass
(retrieved 2026-10-02):

- GLiNER2-PII — https://arxiv.org/abs/2605.09973 ; model card https://huggingface.co/fastino/gliner2-privacy-filter-PII-multi
- OpenAI Privacy Filter — https://huggingface.co/openai/privacy-filter ; evaluation https://arxiv.org/abs/2608.02616
- NVIDIA GLiNER-PII — https://huggingface.co/nvidia/gliner-PII
- GLiNER Guard — https://arxiv.org/abs/2605.05277
- DeBERTa on PIIBench — https://arxiv.org/abs/2605.25816
- Presidio governance move — https://particula.tech/blog/presidio-vs-gliner-pii-redaction-llm ; https://github.com/data-privacy-stack/presidio
- Guardrail evasion — https://arxiv.org/abs/2504.11168
- parallel-decision — https://github.com/thecodacus/llama.cpp/tree/parallel-decision
- Claude Code gateway guide — https://code.claude.com/docs/en/llm-gateway-protocol ; https://code.claude.com/docs/en/llm-gateway
- LiteLLM guardrail log incident — https://docs.litellm.ai/blog/guardrail-logging-secret-exposure-incident
- LiteLLM PyPI compromise — https://www.netspi.com/blog/executive-blog/ai-ml-pentesting/litellm-supply-chain-compromise/
- LiteLLM CVE-2026-59821 — https://osv.dev/vulnerability/CVE-2026-59821 ; v1.102.0 notes https://ai-tldr.dev/releases/litellm-v1-102-0/
- LiteLLM custom guardrails — https://docs.litellm.ai/docs/proxy/guardrails/custom_guardrail
- Ollama DNS rebinding — https://www.nccgroup.com/research/technical-advisory-ollama-dns-rebinding-attack-cve-2024-28224/
- let-localhost-be-localhost — https://datatracker.ietf.org/doc/draft-ietf-dnsop-let-localhost-be-localhost/
- NIST SP 800-38G Rev. 1 2pd — https://csrc.nist.gov/pubs/sp/800/38/g/r1/2pd
- NIST SP 800-224 ipd — https://csrc.nist.gov/pubs/sp/800/224/ipd
- NIST SP 800-92r1 ipd — https://csrc.nist.gov/pubs/sp/800/92/r1/ipd
- NIST AC-4 (catalogue reproductions) — https://www.stigviewer.com/controls/nist-800-53/AC-4 ; https://myctrl.tools/frameworks/nist-800-53-r5/ac-4-8
- NIST AI 600-1 — https://airc.nist.gov/docs/NIST.AI.600-1.GenAI-Profile.ipd.pdf
- NIST Privacy Framework 1.1 draft — https://www.hunton.com/privacy-and-cybersecurity-law-blog/nist-releases-updated-privacy-framework
- C2SP signed note / checkpoint — https://blog.transparency.dev/what-2025-holds-for-certificate-transparency-and-the-transparencydev-ecosystem
- OpenTelemetry GenAI conventions status — https://www.truefoundry.com/blog/opentelemetry-genai-semantic-conventions
- systemd credentials — https://systemd.io/CREDENTIALS/ ; https://man7.org/linux/man-pages/man1/systemd-creds.1.html
- CSA Addendum final — https://www.csa.gov.sg/resources/publications/addendum-on-securing-ai-systems/
- Kiji Privacy Proxy — https://www.helpnetsecurity.com/2026/05/01/open-source-pii-privacy-proxy/
- PasteGuard — https://github.com/sgasser/pasteguard
- Secret scanners — https://appsecsanta.com/secret-scanning-tools
- LLM calibration — https://arxiv.org/html/2601.13284v1
</content>
</invoke>

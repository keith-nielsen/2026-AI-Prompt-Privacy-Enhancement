# ADR-0007 — Observation plane: see every sensitive flow, enforce only at the boundary

Status: **proposed** (2026-10-02). **Amended by ADR-0009**: per-identifier digests are sealed
(offline key), distinct counts come from HyperLogLog sketches, live lineage is written as
`first_seen` occurrence fields, and records gain `access_principal`. Operator direction (2026-10-02): "knowing how much PII/sensitive
data is being worked with, even within the approved area, is very critical so that we know the
benefit of the protection and we can keep track of what we are actually protecting." Answers:
per-identifier keyed digests on approved traffic too; coverage = model calls **and** data sources;
local side = observe + threshold alerts, never block. Amends ADR-0001, 0004, 0006.
Sources: [nist.md](../sources/nist.md), [pdpc-genai-guidelines.md](../sources/pdpc-genai-guidelines.md)
(§9.2, §9.3), [csa-agentic-addendum.md](../sources/csa-agentic-addendum.md),
[kent-context.md](../sources/kent-context.md); Hermes source at `/opt/kent-hermes/src` (read only:
`hermes_cli/plugins.py` `VALID_HOOKS`, `model_tools.py` `post_tool_call` call site).

> **Superseded in part by [ADR-0010](ADR-0010-fully-sealed-audit.md) (2026-10-02):** the exposure ledger, coverage report and alert details are produced only by the audit-grade decrypter; real-time signals are health-only and opaque alerts.

## Context

ADR-0006 put PPE only on the cloud leg. That protects, but it is blind to most of the sensitive
data the system handles: every Gent works on the local model only, and most of Kent's work is
local. Without that view you can't say what the protection is worth ("of 4,000 identifiers we
handled this month, 1,000 would have left in clear"), can't keep an inventory of personal data
processing, and can't tell when a new data source starts carrying sensitive data.

Requirements behind this: PDPC GenAI §9.3 "track and designate responsibilities over new data
sources and implement corresponding safeguards" and §9.2 purpose limitation; NIST PM-5(1) (inventory
of PII), CM-12 (information location), CM-13 (data action mapping), SI-4 (monitoring), AU-6
(review); CSA Addendum §4.2 "Every request sent to the AI system and every generated answer is
scanned".

This is the standard DLP split: **monitor data in motion everywhere, enforce at the boundary**.

## Decision

### Two planes, one engine

| | Enforcement plane | Observation plane |
|---|---|---|
| Where | cloud leg only (ADR-0006 egress) | every model leg + data-source entry points |
| Inline? | yes: the request waits for detection | **no**: pass through first, analyse a copy (tap) |
| Changes content? | mask / block / keep local | **never** |
| Detection | full ensemble + arbiter (ADR-0005) | same engine, same verdict cache; arbiter at low priority |
| Audit | `mask`, `block`, `keep_local`, … | `observe` (new), same record format and keys |
| Failure | fail closed | fail **open for traffic**, loud for coverage (gap counted and alerted) |

Shadow mode (PLAN §3) becomes the enforcement plane running in observation mode. One concept, not two.

### Sensor points

```
            data sources                                 model legs
┌──────────────────────────────────┐        ┌──────────────────────────────────────────────┐
│ S3 Hermes plugin (Kent):         │        │ LiteLLM ─┬─► S1 PPE observe ─► llama-server  │
│    post_tool_call → tool name,   │        │          │   (UNIX socket only PPE can open)  │
│    args, result, session id      │        │          └─► S2 PPE enforce ─► cloud           │
│    (built-in and MCP tools)      │        │ stand-alone client ─► S4 PPE ingress ─► …     │
│ S3 Gent tools wrapper (Kent's    │──obs──►│ S5 replies on S1/S2/S4 (model outputs)        │
│    templates/app/gent/tools.py)  │ socket │                                              │
│ S3 SDK: ppe.observe(source, text)│        │                                              │
└──────────────────────────────────┘        └──────────────────────────────────────────────┘
```

- **S1 local model leg.** LiteLLM's loopback deployments (`router`, `fast`) point their `api_base` at
  PPE's observe listener, which forwards to the real server unchanged and taps a copy. The model
  server moves to a **UNIX socket readable only by PPE's group** (llama-server `--host x.sock`), so
  nothing can reach the local model around the sensor. The ADR-0001 zone checks now run on the
  PPE → model hop, where PPE is the client and can use `SO_PEERCRED` (L2) directly. The auto-router's
  own classifier calls are user text too and are observed the same way.
- **S2 cloud leg.** Unchanged enforcement (ADR-0006).
- **S3 data sources**, where sensitive data *enters* the system before any model sees it:
  - Kent (Hermes): a `ppe-observe` Hermes plugin on `post_tool_call` (payload: `tool_name`,
    `args`, `result`, `session_id`, `tool_call_id`, `duration_ms`). This covers file reads, terminal
    output, web fetches, and MCP tools if Hermes routes MCP calls through the same hook (to confirm
    by test). Observe only: the plugin does **not** use `transform_tool_result`.
  - Gents: Kent's own `tools.py` (`read_file`, `read_web_page`, `web_search`, `run_script`) calls a
    small sensor client after each tool. Each Gent gets a per-Gent, write-only observe socket mounted
    into its container.
  - Other apps: `ppe.observe(source=…, text=…)` in the Python SDK.
- **S4 stand-alone ingress** sees everything a stand-alone client sends, local- or cloud-bound.
- **S5 replies.** Model outputs on every leg. Values PPE restored are counted as *echo* (already
  counted on the way in), not new findings; identifiers the model introduces are counted as
  *generated*.

### Sensor API (data-source side)

- Local UNIX socket `observe.sock` (one per Gent for containers). Message:
  `{source: {kind: tool|mcp|file|web|search|script|sdk, name, locator}, caller, session, text}`.
- **Fire-and-forget**, bounded queue, one worker (the same pattern Hermes uses for its outbound
  webhooks). A sensor never blocks a tool call and never returns a verdict. No oracle for the
  sender; nothing it sends can change agent behaviour.
- Peer identity from `SO_PEERCRED` (uid → `kent`, `gent-<id>`, operator), not from the message.
  `caller` in the message is only a hint. Rate-limited per peer.
- `locator` (file path, URL) can itself be personal data (`/home/…/jane-doe-medical.pdf`): store
  the URL host or the path's top-level workspace area in clear, the full locator only as
  `HMAC(k_aud[p], locator)`.
- Drops (queue full, PPE down) are counted per sensor and reported as **coverage gaps**.

### What is recorded (amends ADR-0004)

New event `observe`. Same record format and same `k_aud[p]` keys, so retention and crypto-shredding
(ADR-0003) apply unchanged:

```
event      observe
flow       source | prompt | reply_generated | reply_echo
zone       loopback | cloud | source
source     {kind, name, host_or_area, locator_digest}   (flow = source only)
value_digest, class, type, detectors, caller, session/conv, req_id, model?, norm_v, key_ids
```

- **Per identifier** (operator choice): `value_digest` on every observed finding, so you can answer
  "was this NRIC processed locally, by whom, from which source, when?" (inventory, investigations,
  data-subject requests).
- Deduplicate per (session, value_digest, flow, zone, source kind) per epoch, as on the enforcement side.
- **Lineage** falls out of the digests: within a session, the same `value_digest` seen at
  `source` → `prompt (loopback)` → `prompt (cloud, masked)` → `reply_echo` is one identifier's path
  through the system (NIST CM-13 data action mapping). Reports reconstruct it from records; there is
  no separate lineage store.
- Trade-off accepted by the operator: the audit now holds pseudonymised digests for **all**
  processing, not just egress. It is a larger target (threat model §5) and stays under the same
  access, rate-limiting and shredding rules.

### Exposure ledger (the "benefit of protection" report)

`ppe report exposure --period 2026-10`:

| Measure | Meaning |
|---|---|
| distinct identifiers handled | count of distinct `value_digest` per class (exact within a period) |
| by zone | stayed on loopback / went to cloud masked / blocked / kept local / passed (allowed class) |
| **protection outcome** | of the identifiers that were bound for cloud: % masked, % blocked, % re-routed local, % passed by policy |
| by caller | Kent, each Gent, operator, stand-alone clients |
| by source | which tools, MCP servers, file areas and web hosts bring sensitive data in; new sources this period |
| generated vs echoed | identifiers the models introduced vs repeated |
| **coverage** | share of model calls and tool calls that passed a sensor; sensor drops; endpoints without a sensor |

Every count is shown next to its coverage figure. A count without coverage is not evidence.

### Threshold alerts (local side: observe + alert, never block)

Shipped as Prometheus rules over counters (no content in labels):

1. **Bulk volume**: distinct identifiers of a class per caller per hour above a baseline multiple
   (e.g. a Gent suddenly handling hundreds of NRICs).
2. **Secrets in local flows**: any `secret` in a local prompt or tool result. It doesn't leave the
   host, but it now sits in the local model's context, the Gent workspace, and maybe its logs.
3. **New sensitive source**: a source (`kind`, `host_or_area`) appears with `special` or ID classes
   for the first time.
4. **Declared vs observed purpose** (PDPC §9.2): a Gent's `project.yaml` may declare
   `data_classes: [...]`; alert when the Gent handles classes outside that declaration.
5. **Coverage**: sensor heartbeat missing, sensor drop rate > 0, a model endpoint seen without its
   sensor (e.g. something talks to llama-server outside PPE: socket-permission drift).
6. Generated identifiers in replies above baseline (a model fabricating or leaking identifiers).

### Cost control

- The verdict cache is shared across planes. A tool result analysed at S3 is a cache hit when the
  same text shows up in the next prompt at S1/S2. Agent loops resend history, so steady-state cost
  is about one analysis per new piece of text, wherever it first appears.
- Observation is asynchronous, so the local model's latency doesn't change.
- Arbiter (parallel-decision) for observation runs at **low priority**, only when the GPU/CPU queue
  is idle. Observation records carry `arbiter: pending|done|skipped`. The enforcement plane always
  preempts.
- Under sustained overload the observe queue sheds work and counts it as a coverage gap. It never
  slows enforcement or the local model.

## Consequences

- Positive: answers "what are we actually protecting" with numbers; gives an inventory and lineage
  of personal data processing; turns shadow mode into a permanent capability; puts PPE on every model
  path, which also hardens the loopback check (PPE is the only client of the local model).
- Negative: about 2–5× more text analysed (all local traffic, tool results) — mitigated by the shared
  cache and async taps, but CPU use must be measured. The audit becomes an inventory of processing
  (larger privacy footprint, accepted). New moving parts: Hermes plugin, Gent sensor client, observe
  sockets mounted into Gent containers (a new channel from Gent to host: write-only, rate-limited,
  peer-checked).
- Kent changes: llama-server to a UNIX socket; LiteLLM `router`/`fast` `api_base` → PPE observe;
  `ppe-observe` Hermes plugin; Gent `tools.py` sensor client and socket mount; conformance checks
  for coverage.

## Alternatives considered

- *LiteLLM callback in logging-only mode for local calls*: sees model calls but not data sources,
  is bypassed by anything that talks to llama-server directly, and runs inside LiteLLM's logging
  path (the 2026 leak surfaces). Rejected as the sensor; fine as an extra signal.
- *Mirror traffic at the network level (pcap)*: loopback/UNIX-socket traffic and TLS make it
  impractical, and it can't see tool results. Rejected.
- *Counts only on local traffic*: smaller footprint, but no inventory or lineage. Operator chose
  digests.
</content>
</invoke>

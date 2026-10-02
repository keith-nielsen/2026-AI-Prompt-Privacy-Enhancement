# ADR-0006 — Interface and topology: PPE as the egress guard; LiteLLM as an optional router in front

Status: **proposed** (2026-10-02), **amended by ADR-0007** the same day: PPE now sits on *both*
legs of the router. The local leg gets an observe listener (pass-through, tapped, never modified)
and the cloud leg keeps the enforcement described here. The model server moves to a UNIX socket
only PPE can open. Read this ADR for the enforcement leg and ADR-0007 for the observation plane.
**Changes PLAN §3/§4**: masking moves from LiteLLM's
`async_pre_call_deployment_hook` to a PPE egress proxy that every cloud-bound request must cross;
a thin LiteLLM callback remains for keep-local routing and identity. Needs operator confirmation.
Sources: [litellm-hooks.md](../sources/litellm-hooks.md), [litellm-2026.md](../sources/litellm-2026.md),
[claude-code-gateway.md](../sources/claude-code-gateway.md), [nist.md](../sources/nist.md),
[csa-agentic-addendum.md](../sources/csa-agentic-addendum.md).

> **Superseded in part by [ADR-0010](ADR-0010-fully-sealed-audit.md) (2026-10-02):** in production `x-ppe-*` detail headers are off and block errors carry only an opaque reference id; class detail is dev/lab only.

## Context

The operator asked for "a clean and clear interface between the user's prompt entry and the LiteLLM
router". First principles (reference monitor, Anderson 1972; the guard model of cross-domain
solutions): the mechanism that enforces a flow policy must be **N**on-bypassable,
**E**valuable (small enough to review), **A**lways invoked, and **T**amper-proof. Check the
candidate topologies against NEAT:

| Topology | Where PPE sits | Knows real target? | Bypassable? | Evaluable? | Depends on LiteLLM correctness? |
|---|---|---|---|---|---|
| T1 in-process callback (PLAN v0) | inside LiteLLM, deployment hook | yes | yes — any LiteLLM path that skips the hook (pass-through endpoints, batches, files, new endpoint types, hook bugs across versions) | no — inherits LiteLLM's size and release churn | **yes** (hook semantics changed again in 1.102.0) |
| T2 front proxy | client → PPE → LiteLLM | **no** (`auto` routes after PPE) | yes, around PPE to LiteLLM | yes | no, but must mask everything not provably local |
| **T3 egress guard** | client → (LiteLLM) → **PPE** → provider | **yes, structurally**: anything reaching PPE's egress listener is cloud-bound | **no**, with host egress control (only PPE's account reaches provider domains) | yes — one small proxy | no |

## Decision

**T3, plus a thin advisory callback.** One PPE service, two listeners on loopback/UNIX sockets:

```
                  ┌─────────────── trust boundary: this host ────────────────────────────────┐
user / IDE / CLI ─┼─► [ingress] ──┐                                                         │
(stand-alone)     │   PPE         │ same engine: detect → decide → mask → forward → restore │
                  │               ├────────────────────────────────────────────► provider API (cloud)
Kent / LiteLLM ───┼─► LiteLLM ──► [egress] (cloud deployments' api_base = PPE)              │
                  │      │                                                                  │
                  │      └──► [observe] ──► llama-server (UNIX socket, PPE-only) — unmodified│
                  │            (ADR-0007: tapped, counted, audited; never blocks)            │
                  └──────────────────────────────────────────────────────────────────────────┘
```

- **Stand-alone users** point clients at PPE's ingress (`ANTHROPIC_BASE_URL=http://127.0.0.1:8787/anthropic`,
  `OPENAI_BASE_URL=http://127.0.0.1:8787/openai/v1`, or a UNIX socket where the client supports it).
  PPE forwards to the configured upstream.
- **LiteLLM users** change only the `api_base` of each deployment and leave routing alone: cloud
  deployments → PPE egress (enforce), loopback deployments → PPE observe (ADR-0007), which forwards
  to the local server. Untagged → cloud
  → must go via PPE; `ppe doctor` and Kent conformance fail if any cloud deployment's `api_base`
  bypasses PPE.
- Ingress and egress are the **same code path**; they differ only in how the upstream and caller
  identity are learned. This collapses PLAN delivery shapes 1 and 2 into one tested component.

### The thin LiteLLM callback (optional, advisory)

`prompt_privacy.adapters.litellm` keeps two jobs that need the router's view:
1. **Keep-local routing** before the cloud leg: `async_filter_deployments` drops cloud deployments
   when Stage 1/3b finds a `special` class (shared verdict cache with the egress engine via a local
   socket; or the callback asks the engine). If it is missing or fails, the egress guard still
   protects: it returns a content-policy error (`invalid_request_error` + `content_policy_violation`
   wording, which LiteLLM maps to `ContentPolicyViolationError`) and LiteLLM's
   `content_policy_fallbacks` sends the request to the local tier. *Both paths to be tested.*
2. **Identity and conversation id** forwarding: LiteLLM's `forward_client_headers_to_llm_api`
   carries `x-claude-code-session-id` / `x-ppe-conversation-id` / a caller header to PPE egress;
   PPE trusts these headers **only** from LiteLLM's peer credentials (UNIX socket `SO_PEERCRED`)
   or a per-gateway token.

The callback never masks. Masking in one place only.

### Wire formats (v1)

Anthropic Messages (`/v1/messages`, `count_tokens`, `models`), OpenAI Chat Completions and
Responses (`/v1/chat/completions`, `/v1/responses`), embeddings (policy: mask-only or block —
no restore possible). Streaming SSE for both. Everything else (files, batches, realtime, audio,
OCR) → **blocked by default** with a clear error until a handler exists (fail closed on unknown
endpoints — the open-list rule from Claude Code applies to *fields within* a supported endpoint,
not to unknown endpoints).

Pass-through rules (claude-code-gateway.md): forward `anthropic-*` headers and unknown body
fields unchanged; change only string leaves; keep `system` arrays, `cache_control`, block order;
never touch thinking blocks or signatures; relay error bodies unmodified; stream without buffering
beyond the restore holdback; forward `ping`.

### Presentation (what users see)

- **Normal request**: nothing changes except latency. Response headers `x-ppe-masked: 3`,
  `x-ppe-classes: person,email`, `x-ppe-audit: <req_id>` (counts and classes only).
- **Block**: an error in the client's own wire format (Anthropic `error.type =
  "invalid_request_error"`, OpenAI `error.code = "ppe_blocked"`) whose message names the class,
  the reason, and the audit request id, never the value: *"Blocked by prompt-privacy policy: a
  secret (aws_access_key) was found in message 3. Remove it or use a local model. Audit id 01J…"*.
- **Keep local**: transparent re-route (LiteLLM) or block-with-reason (stand-alone without a
  loopback target).
- `ppe scan FILE|-`: offline report of what would be masked/blocked (no network).
- `ppe tail`: live view of the metadata projection (classes, actions, models) for the operator.
- No web dashboard in v1 (attack surface on a plaintext-holding process).

### Configuration

- One YAML policy, JSON-Schema-validated at load (`schemas/policy.schema.json`), hash recorded in
  the audit at every load; root-owned `0644`; reload on SIGHUP with a `policy_loaded` record.
- Structure: `profile` (lab | standard | hardened | paranoid), `zones` (deployments/upstreams with
  `privacy_zone`, `kind`, required assurance level), `classes` (class → action, thresholds,
  suppression allowed), `detectors` (enabled, endpoints, timeouts), `scope` (conversation-key
  sources), `audit` (paths, checkpoint cadence), `retention` (periods), `callers` (identity →
  allowed opt-outs).
- Shipped policies: `default.yaml`, `sg-pdpa.yaml`, `eu-gdpr.yaml`, `paranoid.yaml` (everything is
  cloud; no opt-outs).
- Secrets (keys, client tokens, upstream API keys if PPE holds them) never in YAML: systemd
  credentials or `0600` files referenced by path (ADR-0003).

### Provider credentials

PPE forwards the caller's provider credential (header pass-through) by default, so it holds no
provider keys. Option: PPE holds the provider key itself and clients hold only a PPE token (the
Claude Code gateway model) — better for organisations, adds a key to custody.

## Consequences

- Positive: enforcement no longer depends on LiteLLM hook semantics or version; one component
  serves stand-alone and gateway users; non-bypassability becomes an egress-firewall property that
  `ppe doctor` can check; LiteLLM CVEs and its March 2026 supply-chain compromise stop being able to
  disable masking by themselves.
- Negative: PPE must implement provider wire formats and streaming correctly (it had to for the
  stand-alone proxy anyway); LiteLLM sees plaintext (it is inside the trust boundary — its logging
  and callbacks must be local-only, ADR-0004); keep-local via fallbacks needs testing; one more hop
  (loopback, sub-millisecond plus detection time).
- The PLAN's "mask in `async_pre_call_deployment_hook`" becomes the **fallback design** if T3
  proves impractical in testing; its research stays valid.
</content>
</invoke>

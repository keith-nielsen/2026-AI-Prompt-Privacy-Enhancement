# Kent harness context (sibling repo `harness-kent`, GitHub keith-nielsen/2026-AI-Harness-Kent)

## Gateway today

- One LiteLLM proxy for all traffic (`kent-litellm`, account `litellm`, 127.0.0.1:4000). Tiers:
  `router` (local classifier), `fast` (local llama.cpp), `smart` and `frontier` (cloud, Anthropic),
  `auto` (complexity router → one of them). Config: `configs/litellm_config*.yaml`.
- `install/services/litellm/kent_gateway.py`: `custom_auth` (identity from per-identity systemd
  credentials: operator, kent, gent, metrics), per-identity model policy (gent = local only),
  restricted request shape, tool-history repair, `KentActivityLogger` (metadata only; content never
  in Loki).
- Identities reach cloud tiers: `operator`, `kent`. Gents are local-only, so Gent text reaches the
  cloud only through Kent's escalations — which pass the gateway like any Kent call.
- Sim flavours: `sim` / `sim-routed` send smart and frontier to an oracle queue (Claude answering by
  hand) — usable as an end-to-end check that the cloud side only ever sees tokens.

## Existing protections (not this package)

- tirith 0.4.2 pre-exec command scanner on Kent's Hermes (commands only).
- Hermes `redact_secrets`: regex masking of secret-shaped strings in tool output and logs (no PII).
- Egress: Squid; Gents behind an internal network and proxy.

## Audit finding this package closes

2026-09-28 external review, **F-08 (High)**: no DLP or redaction before prompts leave the host; no
local-only mode for regulated data. Addendum 4.1 PII detection on inputs = Gap; 4.2 output PII = Partial.

## Design decisions carried over from the 2026-10-02 discussion

- Scan only traffic whose **selected deployment** is cloud; local traffic untouched.
- Secrets: block (or one-way mask). PII identifiers: swap and restore. Most sensitive classes: keep
  local (re-route to `fast`) rather than mask.
- Mask identifiers (names, passport/NRIC/FIN, street address, phone, email); keep attributes the task
  may need (nationality, country, city).
- Token `<TYPE_xxxxxxxxxx>` = truncated HMAC(key, conversation id | type | normalised value):
  stable within a conversation (no collisions; prompt cache still hits), unlinkable across
  conversations; no host / container / PID inside.
- Audit record per masked value: token, value digest = HMAC(key, type | normalised value), entity
  type, caller identity, conversation/trace id, request id, tier/model, timestamp, key id. Never
  plaintext, never Loki.
- Verdict cache per message hash (agent loops re-send the history).
- Injection classifiers: logged signal only, never the defence.
- Shadow (log-only) first.

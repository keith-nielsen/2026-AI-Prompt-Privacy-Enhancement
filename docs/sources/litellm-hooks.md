# LiteLLM 1.100.1 — hooks and existing guardrails (code read 2026-10-02, behaviour not yet tested)

Installed at `/opt/kent-litellm/lib/python3.12/site-packages/litellm` on the Kent reference host.

## `CustomLogger` hooks that matter (`litellm/integrations/custom_logger.py`)

| Hook | When | Use here |
|---|---|---|
| `async_pre_call_hook(user_api_key_dict, cache, data, call_type)` | proxy, before routing | sees requested model (`auto`, `smart`...), identity; detection + cache warm-up |
| `async_pre_routing_hook(model, request_kwargs, messages, ...)` | "called before the routing decision is made"; used by the auto-router | candidate for "cap at local" on `auto` |
| `async_filter_deployments(model, healthy_deployments, messages, ...)` | router, picking a deployment | drop cloud deployments when policy says keep local |
| `async_pre_call_deployment_hook(kwargs, call_type)` | "modify the request AFTER a deployment is selected, but BEFORE the request is sent" (`utils.py:1253`, called at `utils.py:1780`) | **mask here**: the real target is known, so `auto` resolved to a cloud tier is caught |
| `async_post_call_success_deployment_hook(request_data, response, call_type)` | right after the deployment answers | restore (non-streaming) |
| `async_post_call_success_hook` / `async_post_call_streaming_iterator_hook` | proxy, response to client | restore; streaming restore across chunk boundaries |

Open questions to settle by test: does per-request state set in the deployment hook reach the
streaming iterator hook; do fallbacks re-enter the deployment hook (they should, each attempt is a
deployment call); does the auto-router's own classifier call (`router` tier, local) pass through the
hooks (it must not be masked — local).

## Built-in guardrails

- `guardrail_hooks/presidio.py`: calls Presidio Analyzer/Anonymizer over HTTP
  (`PRESIDIO_ANALYZER_API_BASE`, `PRESIDIO_ANONYMIZER_API_BASE`); per-entity `MASK`/`BLOCK`;
  `output_parse_pii: true` replaces with `<ENTITY_n>` numbered left-to-right per anonymised text,
  stores `pii_tokens[token] = original` in request metadata, unmasks content, streamed chunks and
  tool-call arguments. Weakness: position numbering can collide across messages in one request
  (dict keyed by token → later value overwrites earlier); tokens carry no audit value.
- `guardrail_hooks/litellm_content_filter/`: regex + keyword; 82 patterns (secrets: AWS, GitHub,
  Slack, generic API key; cards; IBAN; email; IPs; passports; SG NRIC/phone/postal/UEN/bank, etc.)
  plus category lists incl. `prompt_injection_*`; actions BLOCK / MASK (one-way).
- `presidio_analyzer` is not installed in Kent's LiteLLM venv; Kent's config defines no guardrails.

## Implications

1. Build as a `CustomLogger` (or `CustomGuardrail`) subclass — portable to any LiteLLM proxy.
2. Mask in `async_pre_call_deployment_hook` keyed on the selected deployment's zone tag
   (`model_info.privacy_zone: local|cloud`), not on the requested model name.
3. Reuse Presidio's Analyzer as one detector backend over HTTP; do **not** use LiteLLM's Presidio
   hook for masking (token scheme).
4. Reuse the content-filter pattern list as a reference, but own the regex set (versioned, tested).
5. Pin per LiteLLM version; adapter tests run against each supported version.

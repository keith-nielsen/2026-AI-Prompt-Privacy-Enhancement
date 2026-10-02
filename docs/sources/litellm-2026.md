# LiteLLM — 2026 security events and newer releases (web, 2026-10-02)

Complements [litellm-hooks.md](litellm-hooks.md) (code read of 1.100.1, still the version on the
Kent host). Facts from vendor blog, OSV and press; not reproduced.

| Date | Event | Relevance |
|---|---|---|
| 2026-03-18 | **Guardrail logging secret exposure** (fixed 1.82.3): custom guardrails that returned the full request dict leaked `secret_fields.raw_headers` (plaintext `Authorization`) into spend logs (UI), OpenTelemetry traces and downstream observability | a guardrail's *return value* is logged → PPE hooks return minimal objects, never request dicts or texts |
| 2026-03-24 | **PyPI supply-chain compromise**: litellm 1.82.7 and 1.82.8 (maintainer token stolen, "TeamPCP") shipped a `.pth` payload that ran at interpreter start and exfiltrated SSH keys, `.env`, cloud creds, kube configs; live < 5 h | the gateway process is a high-value target; PPE must not share a venv with LiteLLM in hardened mode, keys must not be readable by the LiteLLM process if avoidable; hash-locked installs |
| 2026 | CVE-2026-59821 (custom code guardrail create/update without sandbox → code exec, < 1.82.0-stable); CVE-2026-12797 (banned-keywords authorization bypass via prompt, ≤ 1.82.5); CVE-2026-42208 (pre-auth SQL injection; provider keys readable) | the router is not a security boundary to lean on; PPE's guarantees should not depend on LiteLLM's correctness |
| 2026-09-22 | **v1.102.0**: post_call guardrail pipelines run on streaming responses (mid-stream text and tool-call rewrites); scan ids mapped to guardrail/stage/provider | the streaming-restore hook story changes after 1.100.1; adapter tests need a version matrix |

Code detail (1.100.1, `integrations/custom_guardrail.py`): `_process_response` calls
`verbose_logger.debug("Guardrail response: %s", response)` — at debug level any text a guardrail
returns is logged. **LiteLLM must never run at debug log level with PPE**, and PPE's conformance
check should assert the log level.

Guardrail modes (`pre_call`, `during_call`, `post_call`, `logging_only`) and the unified
`apply_guardrail(inputs={texts, images, tool_calls}, request_data, input_type)` API run **before
routing** for `pre_call`; the selected deployment is not known there. The deployment-level hooks in
litellm-hooks.md remain the only in-process point where the real target is known.

## Implications

1. Treat LiteLLM as *inside* the plaintext boundary but *not* as an enforcement point PPE trusts:
   the strongest design puts PPE on the egress path itself (ADR-0006), with LiteLLM pointing its cloud
   deployments at PPE.
2. Never place plaintext in anything LiteLLM logs (return values, metadata, exceptions).
3. Separate venv / service account for PPE; LiteLLM gets no read access to PPE keys.
</content>
</invoke>

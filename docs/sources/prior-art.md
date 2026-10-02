# Prior art — local PII proxies for LLM APIs (2026-10-02)

GitHub metadata via API; READMEs read where noted. None evaluated hands-on.

| Project | Licence | Stars / last push | Shape | Detection | Swap/restore | Notes |
|---|---|---|---|---|---|---|
| `sgasser/pasteguard` (README read) | Apache-2.0 | 758 / 2026-08-25 | local proxy (`/openai/v1`, `/anthropic`, `/codex`), browser extension, dashboard | PII + secrets | placeholders, restored in responses | closest analogue; quick-start `docker run -p 3000:3000` publishes on **all interfaces** (anti-pattern for a plaintext-holding proxy) |
| `dataiku/kiji-proxy` | Apache-2.0 | 436 / 2026-10-01 | local gateway; macOS PAC, Linux HTTP proxy env, Chrome ext. | quantised DistilBERT (ONNX), 16+ types | **realistic dummy values**, restored | fakes can be mistaken for real data or acted on by agents (see ADR-0002) |
| `occludra/gateway` (was aisecuritygateway) | Apache-2.0 | 44 / 2026-08-16 | OpenAI-compatible proxy | PII, injection, secrets | redact | |
| `daslabhq/pii-proxy` | MIT | 7 / 2026-07-21 | Node library/proxy for agents | local | mask/unmask | |
| `protectai/llm-guard` | MIT | 3,213 / 2026-07-08 | Python scanners library | many scanners incl. Anonymize/Deanonymize (Presidio-based vault) | yes | library, not proxy |
| LiteLLM Presidio hook | MIT | — | in-gateway | Presidio | `<ENTITY_n>` positional | rejected (collisions, no audit value) — RESUME |

## What none of them provide (the gap PPE fills)

1. Zone-aware enforcement (mask only on the cloud leg; verified loopback for "local").
2. Keyed, conversation-scoped, deterministic tokens with byte-stable history (preserved thinking and
   prompt caching survive).
3. A tamper-evident, plaintext-free audit trail with crypto-shredding retention and audited lookups.
4. Published per-class detection metrics on a synthetic corpus (PDPC §8.3).
5. A controls mapping (NIST 800-53 AC-4 family, PDPC, CSA, EDPB).
</content>
</invoke>

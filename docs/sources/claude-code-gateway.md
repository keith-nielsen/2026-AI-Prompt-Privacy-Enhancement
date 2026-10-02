# Claude Code gateway compatibility (code.claude.com docs, read 2026-10-02)

Pages read: `llm-gateway` and `llm-gateway-protocol` (the gateway compatibility guide). Claude Code is
the most demanding stand-alone client PPE will face; other clients (OpenAI SDK, Codex, IDEs) are
simpler. Facts quoted from the docs.

## Requirements that constrain PPE

- Endpoints: `POST /v1/messages` (path match; Claude Code appends `?beta=true`),
  `/v1/messages/count_tokens` optional, `GET /v1/models?limit=1000` (3 s timeout, **redirects treated
  as failure**), `HEAD /api/hello` warm-up probe (may be rejected).
- **Forward unchanged:** `anthropic-version`, `anthropic-beta` ("don't allowlist individual values");
  all `anthropic-*` headers and body fields as open lists; error bodies unmodified (client retry logic
  matches upstream wording); `retry-after`, `x-should-retry`, `anthropic-ratelimit-unified-*`.
- Streaming: relay events as they arrive (buffering whole responses stalls the client); never drop,
  duplicate or reorder events; forward `ping` events (client aborts after 5 min of silence).
- **"A gateway that rewrites or redacts request bodies for content inspection breaks the pairing the
  same way stripping does, so inspect without modifying."** (feature pass-through). The pairing is
  beta header ↔ body field; masking string content inside text fields does not remove fields, but
  any structural rewrite (dropping blocks, converting `system` arrays to strings, moving
  `cache_control`) does.
- **Preserved thinking:** the API rejects thinking blocks "bound to a different conversation" when
  `system`, `tools`, or earlier `messages` content differs from the request that produced the
  thinking. Claude Code then drops earlier thinking blocks and retries.
- **Prompt caching:** "Forward `cache_control` unchanged wherever it appears, and don't convert
  block-form `system` or message content to plain strings"; otherwise every turn bills uncached.
- System prompt attribution block: keep the `system` array exactly as received, block first.
- Identity / correlation headers the gateway may consume: `x-claude-code-session-id` (one per
  session), `x-claude-code-agent-id`, `x-claude-code-parent-agent-id`; optional hint headers
  (`x-claude-code-prompt-id`, `x-claude-code-request-class`, compaction markers) with
  `CLAUDE_CODE_GATEWAY_HINT_HEADERS=1`.
- Managed setting `allowedProviders: ["customEndpoint"]` + pinned `ANTHROPIC_BASE_URL` makes the
  gateway "the only destination a managed machine may use" (Claude Code ≥ v2.1.285).
- Some calls bypass `ANTHROPIC_BASE_URL` and go straight to `api.anthropic.com` (fast-mode
  availability check, WebFetch domain safety check).
- Cursor (forum + vendor docs): the "Override OpenAI Base URL" applies to Ask mode only; Agent, Tab,
  inline edits use Cursor-managed paths. Whether the override is called from Cursor's servers (making
  a `127.0.0.1` proxy unreachable) was **not confirmed** — open question.

## Implications

1. **Determinism is a hard requirement, not an optimisation.** The masked form of every earlier turn
   must be byte-identical on every resend, or preserved thinking breaks and the prompt cache misses.
   Keyed per-conversation tokens give this *if* the scope and key are stable for the conversation
   and the restore→re-mask round trip is the identity (ADR-0002, invariant R3).
2. Mask only inside string leaves (`text`, `input` values, tool-result content); never restructure.
   Leave `thinking` / `redacted_thinking` blocks and their `signature` untouched.
3. Conversation scope for Claude Code = `x-claude-code-session-id` (keyed-hashed before use). It
   changes on `/clear` and new sessions, which matches "document-randomised" pseudonyms.
4. Streaming restore must hold back only the bytes that could be a partial token, and must pass
   `ping` and all other events through in order.
5. Non-bypassability for Claude Code: managed `allowedProviders` + egress block of
   `api.anthropic.com` for every account except PPE's (the direct calls in the last bullet then fail
   closed, which is the intended behaviour; fast mode degrades).
</content>
</invoke>

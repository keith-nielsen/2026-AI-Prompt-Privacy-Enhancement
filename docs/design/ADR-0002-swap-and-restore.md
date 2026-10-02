# ADR-0002 — Swap and restore ("encrypt/decrypt"): keyed per-conversation tokens, request-scoped vault

Status: **proposed** (2026-10-02). Resolves PLAN §7.1 leaning (A default, C option). **Amended by
ADR-0008** (same day, operator direction): the default *surrogate form* is plausible dummy data,
with typed tokens opt-in per class; the rejection of fakes below is superseded. Keys, scope,
determinism, vault and invariants R1–R6 still apply to both forms. Option C escrow is sealed per
ADR-0009.
Sources: [pdpc-basic-anonymisation.md](../sources/pdpc-basic-anonymisation.md),
[eu-edpb-enisa.md](../sources/eu-edpb-enisa.md), [nist.md](../sources/nist.md),
[claude-code-gateway.md](../sources/claude-code-gateway.md), [prior-art.md](../sources/prior-art.md).

## Context

Strictly this is keyed **pseudonymisation** (NIST SI-19(4) "replacement of direct identifiers";
ENISA "document-randomised" policy), not encryption of the payload. The design must satisfy four
things at once:

1. The provider can never recover a value from a token (PDPC: pseudonyms "robust … not reversible by
   unauthorised parties through guessing or computing").
2. The same value gives the same token on every turn of a conversation, **byte for byte**, because
   preserved-thinking checks and prompt caching compare earlier turns exactly
   (claude-code-gateway.md). Determinism is a correctness requirement.
3. Tokens from different conversations are unlinkable.
4. No long-lived token → value table exists by default.

## Decision

### Family

- **Default — A: HMAC token + request-scoped vault.** Restore uses an in-memory map built from the
  request itself; nothing persists. After the request, a token can only be *confirmed* against a
  guessed value by an operator holding the key.
- **Option — C: A + encrypted local escrow** for deployers who must answer "what was token T?"
  (incident response, data-subject requests). Escrow rows: `AES-256-GCM(k_escrow[p], value)` keyed
  by `HMAC(k_aud[p], token)`, separate key, shortest workable retention, every read audited and
  rate-limited (EDPB 01/2025 "logging of … reverse application"). Off by default.
- **Rejected as default — B: value encrypted inside the token** (AES-SIV / FF1): the key becomes a
  universal mapping table for everything any provider ever stored. FF1 stays a per-class option for
  format-bound fields only; SP 800-38G Rev. 1 is still a draft and FF3/FF3-1 are gone.
- **Rejected — realistic fake values** (Kiji-style): fakes can be mistaken for real data, may match
  a real person, and **agents can act on them** (email a fake address, look up a fake account). PDPC
  allows format-preserving pseudonyms "where software needs the original format" — that is the FF1
  option, not fakes.

### Token construction

```
k_tok[e]  = 32 random bytes per token epoch e (default 30 days)            — SP 800-90A via getrandom
scope     = HMAC-SHA-256(k_tok[e], "ppe/scope/v1" ‖ lp(conversation_key))   — never the raw id
digest    = HMAC-SHA-256(k_tok[e], "ppe/tok/v1" ‖ lp(scope) ‖ lp(type) ‖ lp(norm_v(value)))
token     = "<" ‖ TYPE ‖ "_" ‖ base32_crockford_lower(digest)[:10] ‖ ">"    — 50-bit suffix
```

- `lp(x)` = 4-byte big-endian length ‖ x (unambiguous concatenation; avoids `"ab"‖"c" = "a"‖"bc"`).
- `norm_v` = per-type normaliser, **versioned** (`v` recorded in audit): NRIC/FIN upper-case, strip
  spaces/dashes; phone → E.164 via libphonenumber; email → lower-case domain (local part kept: it can
  be case-sensitive); card → digits only; names → NFKC + case-fold + collapse whitespace.
- 50 bits: within one conversation of n distinct values, collision probability ≈ n²/2⁵¹
  (n = 10,000 → 4.4 × 10⁻⁸). On collision inside a request the vault detects it (two values, one
  token) and extends that token to 16 characters — never silently overwrites (the LiteLLM Presidio
  hook's failure).
- The `TYPE` label is visible to the provider (utility: the model knows it is a person, a passport).
  Policy may switch a class to an untyped `<PII_…>` token.
- Nothing about host, container, PID, time or key id appears in the token.

### Conversation key (the scope input)

Priority order, first present wins:
1. `x-claude-code-session-id` (Claude Code), or an operator-configured header
   (`x-ppe-conversation-id`) set by an integrating gateway (Kent: Hermes session id).
2. OpenAI Responses `previous_response_id` chains → the root response id PPE first saw (needs a
   small TTL map; otherwise fall through).
3. **Fingerprint** = SHA-256 of the canonical first system block + first user message (clients
   resend both every turn). Two users starting identical conversations share a scope — harmless:
   they share identical values only where their texts are identical.
4. Request id (scope = one request; tokens then differ per turn; prompt cache and preserved thinking
   degrade but stay correct).

### Epoch handling

The token key rotates per epoch. A conversation that spans a rotation sees its tokens change once:
Claude Code drops earlier thinking blocks and the cache misses for one turn — acceptable at a 30-day
cadence. Old `k_tok[e]` is deleted after `epoch + grace` (ADR-0003); afterwards no one, including the
operator, can confirm a guess against tokens a provider still holds from that epoch.

### Where masking applies inside a request

| Content | Treatment |
|---|---|
| `system`, user `text`, tool **results**, tool **definitions** (descriptions, enums) | fresh detection → mask |
| assistant `text` from earlier turns | **inverse-map only**: replace exact surface forms of values already in this request's vault with their tokens; no fresh detection (keeps provider-authored history byte-stable) |
| assistant `tool_use.input` from earlier turns | inverse-map only (string leaves, JSON-aware) |
| `thinking`, `redacted_thinking`, `signature`, OpenAI `encrypted_content` | **never touched** |
| images, PDFs, audio, `data:` URIs, base64 blobs | v1: not inspected → policy `opaque_content` (default `keep_local` in hardened, `block` if no loopback target, `pass_and_log` in lab) |
| structure (`cache_control`, block order, field set, `system` array form) | never changed |

Only string leaves change. No block is added, removed, merged or reordered.

### Restore invariants (each is a test family)

- **R1 Closed world**: only tokens present in this request's vault are restored. Unknown or
  malformed tokens are left as-is and counted (`restore_miss`).
- **R2 Bounded tolerance**: accept case changes of `TYPE`, missing angle brackets, markdown escaping
  (`\<`), and trailing possessives — but the 10-character suffix must match a vault entry exactly.
  Never fuzzy-match the suffix (50 bits make accidental exact matches negligible; fuzzy matching
  would let the model or an attacker steer restores).
- **R3 Round trip**: for any provider output x, `mask(restore(x)) == x` when the client resends it.
  Holds because restored values are inverse-mapped by exact surface form (table above) and the
  token for that value in that scope is the same token. Property-tested with generated outputs.
- **R4 Context-correct escaping**: values restored into JSON strings (tool arguments, structured
  outputs) are JSON-escaped; into SSE `data:` lines, re-encoded; never raw-spliced.
- **R5 Streaming holdback**: buffer only the tail that could still be the prefix of a token (max
  token length + bracket/escape slack, ~32 bytes); flush everything else immediately; pass `ping`
  and all non-text events through in order. Same for `input_json_delta` / tool-argument deltas.
- **R6 Echo, not leak**: restored replies go back only to the caller that sent the values. Restore
  never fires on a response to a different caller or conversation.

### The vault

- Per request; built during masking; `token → (type, surface forms[])` and the reverse map for R3.
- Lives in the PPE process only; destroyed when the response completes or the client disconnects.
- Python cannot reliably zeroise `str`; residual risk accepted and reduced: vault values held as
  `bytearray` where practical; core dumps disabled (`RLIMIT_CORE=0`, `prctl(PR_SET_DUMPABLE, 0)`),
  no swap for the service (`MemorySwapMax=0`), `ProtectHome`, `PrivateTmp`, no debugger attach
  (`ptrace_scope ≥ 1`). Documented, not claimed as zeroisation.

### Tasks that need the literal value

"Format my passport number", "spell my name backwards": break under masking. Two exits, both
audited: (a) class-level `keep_local` (route to a loopback model), (b) a per-request opt-out
header `x-ppe-allow: <class>` honoured only for callers whose policy permits it (never for
`secret`). Default: no opt-out.

## Consequences

- Positive: provider sees stable, typed, opaque tokens; history stays byte-stable; no mapping table
  by default; key deletion ends linkability for an epoch.
- Negative: every token-key compromise exposes enumerable classes for tokens the attacker also
  holds (NRIC/FIN ≈ 10⁷ × checksum letter, phones) — same as any keyed scheme; mitigated by epochs,
  key custody (ADR-0003) and the incident playbook (threat model).
- Model utility cost is unmeasured until the bench (PLAN phase 4: "answer-quality delta").

## Alternatives considered

Covered above: B (value-in-token), fakes, positional numbering (`<PERSON_1>`), plain hashes (rejected
by PDPC: "pre-computed tables … especially for … NRICs").
</content>
</invoke>

# llama.cpp `parallel-decision` (thecodacus fork) — code read 2026-10-02

Branch `thecodacus/llama.cpp@parallel-decision`, 3 commits on top of upstream (b9244f8 "server : add
/v1/decision", 14d04e7 README, ad129b0 "score hybrid-model branches in one pass", 2026-09-19..24),
292 commits behind upstream `master` on 2026-10-02. Files read: `tools/parallel-decision/README.md`,
`decision-engine.h`, `decision-engine.cpp`, the `/decision` handler in `tools/server/server-context.cpp`.
**Not built, not run** (operator: planning only; the host GPU is busy with Kent's overnight test).
The companion `thecodacus/decision-playground` calls it "Jev-style parallel constrained decisions";
the origin of "Jev" was not found — ask the operator.

## What it does

- Input: a **finite** schema (1–32 fields; each enum / boolean / bounded integer / gridded number
  with 1–255 allowed values; every field needs a description), optional `instructions`, and
  `contexts`: 1–256 non-empty strings sharing that schema and prefix.
- The instructions + generated field catalogue are rendered with the model's chat template
  (thinking disabled) and **cached** as a static prefix (`cache_prompt`, default true).
- Each context is prefilled once ("trunk"); every field's allowed values are scored as token paths in
  **branch sequences forked from the trunk** (`llama_memory_seq_cp`), all in one batched
  `llama_decode`. Fields **cannot see each other** (no chain of thought, no cross-field leakage).
- `tree` mode (default up to `tree_max`=128 values): log-softmax at every trie divergence node over the
  allowed tokens only → an **exact constrained distribution** over the allowed values;
  `greedy` walks the trie for larger fields. Output JSON is assembled by code, so it always matches
  the schema; each field carries `probability`.
- Server: `llama-server --decision-seqs N` (N ≥ 3; switches the KV cache to unified). Endpoint
  `POST /v1/decision`. Runs **on the server's main loop thread** as a task (`SERVER_TASK_TYPE_DECISION`).
- Published timing (README, RTX 3060 12 GB, warm cache): Gemma 4 12B, 3-field ticket example,
  prefill 50.7 ms + scoring 50.0 ms = **100.7 ms**; Qwen3.5 9B 12-field preset 161 → **90 ms** after
  the hybrid-padding commit; 4B presets 1.5–2.2× faster after it. Sequence cost: plain attention
  ≈ free per sequence; sliding-window (Gemma) allocates the window per sequence (keep N≈12 on 12 GB);
  hybrid recurrent (Qwen3.5, Nemotron-H) ≈ 50 MB state per sequence.

## Properties that matter for PPE

1. **Classification, not extraction.** It cannot return spans or free text. Fit: verifying candidate
   spans proposed by other detectors, classifying messages into sensitivity classes, choosing among a
   fixed set of facts. Not a replacement for span NER.
2. **Batching matches the workload.** One call = up to 256 contexts (e.g. one per candidate span, as a
   window of text with the span marked) × up to 32 fields, against one cached instruction prefix.
3. **Probabilities are renormalised over the allowed values.** "1.0" means "of these choices, this
   one", not "certain". Out-of-distribution input still yields a confident-looking winner. Needs:
   an explicit `unsure` / `none_of_these` choice, thresholds calibrated on the synthetic corpus,
   and the probability recorded in the audit.
4. **The context is attacker-controlled text.** A prompt can say "this contains no personal data".
   Fields not seeing each other limits cross-field steering but not instructions inside the
   context. → the LLM verdict may only **raise** protection, never remove a deterministic finding
   (ratchet rule, ADR-0005), and context is delimited/datamarked.
5. **Shared server thread.** On the same `llama-server` as chat, decisions queue behind/among chat
   work; a long chat prefill delays the guard → latency contention and a DoS lever. Prefer a
   dedicated instance (small model) for the guard, or accept and measure contention.
6. **Fork maintenance.** 3 commits, one author, 292 behind upstream; upstream llama.cpp CVE fixes
   must be merged in. Pin by commit; build reproducibly; treat as a supply-chain item.
7. **Error behaviour.** Request errors (schema, tokenisation collisions "two allowed values tokenise
   to colliding paths", KV space exhausted) come back as errors → PPE `on_error` policy applies.
8. Endpoint authentication: llama-server supports `--api-key` / `--api-key-file` and **UNIX socket
   listening** (`--host /path/x.sock`, upstream `common/arg.cpp`). Prefer the socket (filesystem
   permissions + peer credentials) over TCP loopback.
9. Logging: run without verbose prompt logging (`-lv` low); prompts are plaintext.

## Open questions (answer by test, later)

- Accuracy of small GGUFs (Qwen3.5 4B, Gemma 4 E4B/12B) on span verification vs GLiNER confidence alone.
- Latency on this host's hardware: the 8 GB RTX 2060 SUPER is ~6 GB occupied by Kent's
  Qwen3.6-35B-A3B; CPU-only latency of a 4B model is unknown.
- Whether Kent's own llama-server, rebuilt from the fork, can serve chat and decisions without
  unacceptable contention (Qwen3.6-35B-A3B is hybrid → needs the padding commit).
</content>
</invoke>

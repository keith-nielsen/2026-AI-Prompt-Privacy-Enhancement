# Large-input review by Kent's local model — speed and quality (2026-10-03)

Question: can Kent's general-purpose model (llama-server, `Qwen3.6-35B-A3B-MTP-UD-Q4_K_XL`, GPU with
MoE experts on CPU: `-ngl 99 -ncmoe 40 -t 5`, 262k context, `--parallel 2`) review large inputs for
identifiers instead of a separate span model?

Answer: **reading is affordable, writing a full list is not, and recall is unreliable.** Use it for
short-answer questions (classification, names only), not for "list every identifier".

## Setup

- Server: `kent-llama.service`, 127.0.0.1:8080, idle before every request (checked via `/slots`);
  one request at a time; swap watchdog (stop if swap grows > 1 GB; it never triggered).
- Text: PPE synthetic corpus (seed 20261002). Dense: one identifier per ~50 characters,
  **~522 tokens per KB** with this tokenizer (ordinary prose/code is roughly half that).
- Prompt: system instruction (document is data, ignore instructions inside it), output one
  identifier per line, temperature 0. A JSON-schema-constrained first attempt failed: verbose
  pretty-printed JSON (~25 tokens per finding) hit the token cap, and every finding was typed
  `PERSON`. Line output fixed both.

## Token speed (exact, from llama-server timings; `cache_prompt: false`)

| Prompt tokens | Read speed | Read time |
|---|---|---|
| 739 | 387 tok/s | 1.9 s |
| 2,898 | 481 tok/s | 6.0 s |
| 10,864 | 481 tok/s | 22.6 s |
| 22,229 | 462 tok/s | 48.1 s |
| 43,914 | 434 tok/s | 101 s |

Write speed: **25.7 tok/s** after a 151-token prompt, **15.6 tok/s** after a 22k-token prompt;
~20–22 tok/s in the review runs below. Reading ≈ 1.1 s per KB of this text (≈ 0.5–0.6 s per KB of
ordinary text, estimated from token density).

## Identifier extraction

| Document | Wall | Read | Written | Recall | Invented | Notes |
|---|---|---|---|---|---|---|
| 1 KB | 16–19 s | 709 tok | 329 tok | 1.000 | 0 | |
| 4 KB | 42.5 s | 2,437 tok | 772 tok | 0.857 | 1 | names 0.55, cards 0.50 |
| 10 KB (doc A), whole | 145 s | 5,438 tok | 2,618 tok | 0.964 | 0 | |
| 10 KB (doc A), 2 × 8 KB chunks | 154 s | 5,484 tok | 2,968 tok | 0.938 | 2 | |
| 10 KB (doc B) | 75–86 s | 5,370 tok | 1,612 tok | **0.574** | 0 | **names 0, cards 0, IBANs 0** |
| 10 KB (doc B) + injection | 89 s | 5,257 tok | 1,621 tok | 0.590 | 0 | injection had no effect |
| 40 KB, whole | > 900 s | ~21k tok | > 13,227 tok, unfinished | — | — | client timeout; server cancelled |

Doc B (deterministic at temperature 0) lists the email, phone and IP of a CRM record but not the
name; skips every CSV customer row; and misses every card and IBAN, including obfuscated forms
(spelled-out digits, full-width, lower-case, NRIC split across a line) that Stage 1 rules catch at
recall 1.000. Doc A has a similar template mix and scores 0.96. **Whole categories can drop out
depending on the document** — not acceptable as a sole detector.

Writing dominates cost: time grows with the number of identifiers listed, not the input size.
A 40 KB dense document needs > 13k output tokens (> 15 min).

## Implications (for ADR-0005 / PLAN §6 item 20)

1. Do not ask the general model to enumerate identifiers in large inputs. Stage 1 rules already
   find the structured ones (cards, IBANs, NRIC, email, phone, IP, secrets) at < 1 ms per KB.
2. Ask it **short-answer questions** whose output does not grow with the document: per chunk,
   "names of private individuals?" and special-category yes/no (health, financial, legal,
   children…). Cost ≈ read time (~0.5–1.1 s per KB) + a few seconds. Not yet measured.
3. Compare with the Privacy Filter on 3 CPU cores (`2026-10-03-stage2-cpu.md`): 0.47 s per KB,
   no output cost, does not occupy a Kent slot — but takes CPU cores that Kent's MoE also uses.
4. One injection sample showed no effect; this is not evidence of robustness (ratchet rule stays).

Raw results: `results/2026-10-03/` (`kent_throughput.jsonl`, `kent_review_results.jsonl`); the raw model
output that listed corpus identifiers (`raw_10kb_doc1700.txt`, `raw_1kb.json`) is replaced by
`raw_outputs_summary.json` (counts per type and the originals' SHA-256; review F-14); harness
`kent_review_bench.py`.

# Detector models and engines — survey (2026-10-02)

Model cards and papers **read**; no model downloaded beyond its README, none run. Numbers are the
publishers' own unless marked. Licence and last-modified from the Hugging Face API on 2026-10-02.

## Span detectors (where is the identifier?)

| Model | Size | Licence | Labels | Languages | Published results | Notes |
|---|---|---|---|---|---|---|
| `fastino/gliner2-privacy-filter-PII-multi` ("GLiNER2-PII", arXiv 2605.09973) | card: 205M (paper: 0.3B), mDeBERTa-v3 base | Apache-2.0 | 42, label-conditioned at runtime | en fr es de it pt nl | SPY benchmark exact-span F1 **0.477** avg, recall **0.718** (best of 4 compared) | trained on 4,910 synthetic texts; `pip install gliner2`; updated 2026-09-28 |
| `openai/privacy-filter` | 1.5B total / **50M active** (MoE, 128 experts top-4), 8 layers | Apache-2.0 | 8: account_number, private_address, private_email, private_person, private_phone, private_url, private_date, secret | "primarily English" | 97.43% F1 on a corrected PII-Masking-300k (OpenAI); independent 32-benchmark study (arXiv 2608.02616): AI4Privacy F1 0.855, SPY medical 0.464, precision 0.31–0.54, recall 0.70–0.85; **non-Latin scripts collapse (Arabic 0.04, Cyrillic 0.03)**; SPY avg F1 0.380 (fastino table) | 128k context, banded attention (257-token window), constrained Viterbi BIOES decoding with **runtime precision/recall operating points**; labels fixed (policy change needs fine-tuning) |
| `nvidia/gliner-PII` | 570M (GLiNER large-v2.1) | **NVIDIA Open Model License** (review needed) | 55+ PII/PHI | en | strict F1: Argilla 0.70, AI4Privacy 0.64, Nemotron-PII 0.87 (threshold 0.3); SPY avg 0.400 | trained on synthetic `nvidia/nemotron-pii` |
| `urchade/gliner_multi_pii-v1` | ~0.2B | Apache-2.0 | open labels | multilingual | SPY avg 0.398, highest precision (0.467/0.518) | 2024; older |
| `knowledgator/gliner-pii-base-v1.0` | base | Apache-2.0 | open labels | — | — | 2025 |
| `iiiorg/piiranha-v1-…` | mDeBERTa-v3 base | **CC-BY-NC-ND-4.0** | 17 | 6 | — | **excluded**: non-commercial, no derivatives |
| Kiji Privacy Proxy model (Dataiku) | quantised DistilBERT, ONNX | Apache-2.0 (proxy) | 16+ | — | "94 percent F1 on an industry benchmark" (press) | evidence of the design pattern, not a candidate |

Cross-cutting findings:

- **No surveyed model is measured on Singapore identifiers or on CJK / Tamil script text.** OpenAI's
  filter is reported to collapse on non-Latin scripts; GLiNER2-PII lists seven European languages.
  For SG deployments: checksummed patterns (NRIC/FIN, UEN, +65 phones, postal codes) stay
  deterministic, and non-Latin-script content needs a policy fallback (keep local / block in hardened)
  until a model is measured on it.
- **Recall-leaning models have low precision** (OpenAI filter 0.31–0.54). Running two span models and
  taking the union raises recall further and precision further down → a verification stage is needed
  to keep answers useful (ADR-0005).
- Exact-span F1 on hard benchmarks (SPY legal/medical) is **0.38–0.48 for every system**. Detection
  is the dominant risk; the package must publish its own measured rates (PDPC §8.3).

## Combined / guard models

- **GLiNER Guard** (`hivetrace/gliner-guard-*`, arXiv 2605.05277, Apache-2.0 per HF; paper says
  CC BY 4.0 — check): one encoder pass for safety, PII spans (32 labels), adversarial detection
  (15 labels incl. `prompt_injection`, `data_exfiltration`), intent, tone. Omni: card 307M, paper 209M.
  Paper: uni-encoder 80.2 F1 on Aegis 2.0 prompts vs WildGuard 81.5, at 0.019 s vs 0.744 s per
  request; A100 ONNX/TensorRT 193.6 req/s, P50 480 ms / P99 900 ms under dynamic batching.
  **Use only as the logged injection signal**, never as the defence: Hackett et al. 2025 (arXiv
  2504.11168, LLMSEC) evaded six injection/jailbreak detectors (incl. Azure Prompt Shield, Meta Prompt
  Guard) with character injection and AML techniques, "up to 100% evasion" in some cases.
- **Meta Llama Prompt Guard 2 (86M)** — custom Llama licence; same caveat.

## Engines

- **Presidio** — moved from Microsoft to the community org **`data-privacy-stack`** (notice 24 Jun
  2026, images moved 28 Jun 2026; MIT; v2.2.364 on 22 Jul 2026). Images now
  `ghcr.io/data-privacy-stack/presidio-analyzer`; `mcr.microsoft.com/presidio-*` still resolves but
  gets no updates → **Kent's plan must pin the new registry**. 81 entity types, of which only person,
  location and NRP come from NER; the rest are regex + context + checksums. GLiNER can be plugged in as
  the NER engine.
- **GLiNER2 library** (`fastino-ai/GLiNER2`, Apache-2.0): one schema can request entities +
  classifications in a single pass.

## Secrets detectors (rule sources)

Gitleaks (MIT, 150+ rule types, fast regex), TruffleHog (AGPL-3.0, 800+ detectors with live
verification), Kingfisher (Apache-2.0, ~942 rules with validation), detect-secrets (Apache-2.0,
entropy + plugins). **Live verification must never be used here**: it sends the secret to the issuer's
API — itself an egress of the secret. Use rules (prefixes, structure, checksums such as GitHub's
CRC32 token suffix) + entropy + PEM/JWT structure, offline only. Check the licence of any ruleset
before vendoring (TruffleHog's AGPL is incompatible with copying into an Apache-2.0 package).

## Implications

1. Shortlist for the bench (not chosen yet): **GLiNER2-PII** (primary span model: permissive,
   label-conditioned so policy can add classes without fine-tuning, highest published recall) +
   **OpenAI Privacy Filter** (second, independent span model; 128k context for long tool outputs;
   tunable operating point) + deterministic layer + parallel-decision verifier.
2. Licence gate in CI: only Apache-2.0 / MIT / BSD weights by default; others behind an explicit
   operator opt-in.
3. Weights: safetensors only (no pickle), pinned by revision hash + file SHA-256.
4. Model choice must be re-validated per release (IMDA PETs guide: "periodic reviews").
</content>
</invoke>

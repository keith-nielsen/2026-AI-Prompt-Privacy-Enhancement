# Bench harness (2026-10-03/04) — rescued from the session scratchpad

Throw-away measurement scripts behind `bench/2026-10-03-stage2-cpu.md` and
`bench/2026-10-03-kent-model-review.md`. Raw outputs: `bench/results/2026-10-03/`
(`cpu_runs_from_console.txt` holds results that were only printed to the console).
Not part of the package; not linted or tested.

## Rebuild the environment (it lived in /tmp and is gone after reboot)

```bash
cd ~/Documents/repo/prompt-privacy-enhancement/bench/harness
# 1. synthetic corpus (fixed seed 20261002) next to the scripts
../../.venv/bin/ppe corpus --out corpus.jsonl   # --out is a file path; byte-identical to the bench
                                                # corpus: sha256 3a4f7aa9ce4364f1a598d5e9307b3c526d91ac084ebe1e91f2c454f099067664
# 2. benchmark venv (CPU-only torch first, then the rest from PyPI — one combined install hung)
~/ai-env/bin/uv venv --python 3.12 bvenv
~/ai-env/bin/uv pip install --python bvenv/bin/python --index-url https://download.pytorch.org/whl/cpu torch==2.14.1+cpu
~/ai-env/bin/uv pip install --python bvenv/bin/python -r requirements-bench.txt   # pinned freeze
# 3. privacy-filter.cpp (MIT), commit 735a6c28607ee82afc3a670383f41b55266a3b9a, ggml submodule 3af5f57
git clone https://github.com/localai-org/privacy-filter.cpp pfcpp && cd pfcpp
git checkout 735a6c28607ee82afc3a670383f41b55266a3b9a && git submodule update --init --depth 1
nice -n 19 taskset -c 5-7 bash -c 'cmake --preset release && cmake --build --preset release -j3'
```

Without `--out`, `ppe corpus` writes `corpus-out/corpus.jsonl` in the current directory. Keep
`bvenv/`, `pfcpp/` and `corpus.jsonl` untracked (`corpus.jsonl` is git-ignored here).

## Models (never in ~/.cache — see memory `model-files-location`)

All in `/media/administrator/DATA/models` (read-only remount for Kent: `/srv/kent/models`):
`privacy-filter-q8.gguf`, `privacy-filter-f16.gguf`, `openai-privacy-filter/`,
`fastino-gliner2-privacy-filter-PII-multi/`, `okasi-gliner2-privacy-filter-pii-multi-onnx/`
(third-party ONNX export; the scripts import its `examples/onnx_runtime.py` from there).
SHA-256 verified against the Hugging Face API on 2026-10-03.

## Scripts

| Script | What | How it was run |
|---|---|---|
| `bench_one.py <model> <threads>` | one model × thread count, 160 B / 1 / 10 / 100 KB; model = gliner2, pf_torch, pf_onnx_int8, pf_onnx_q4 | via `run_all.sh` — **never run `pf_torch` on 100 KB** (33 GB RSS) |
| `run_all.sh cfg…` | wrapper: pins cores 5-7, nice 19, skips if Kent busy | **stale**: hard-codes an old llama-server PID and has no memory cap — wrap each run in the cap below instead |
| `bench_gliner_variants.py <threads>` | GLiNER2 labels count, batched long API, dynamic int8 | capped |
| `enc.py` | DeBERTa encoder alone, fp32 vs int8 | capped |
| `okasi/bench_onnx.py <threads>`, `okasi/prof.py` | GLiNER2 ONNX int8 speed; preprocessing vs forward split | capped |
| `kent_review_bench.py --dry-run / --throughput / --run` | Kent's llama-server: token speeds, identifier extraction, injection | `KENT_LLAMA_URL` (default `http://127.0.0.1:8080`); refuses unless all slots idle; run with `watchdog.sh` |
| `watchdog.sh <pid> <swap_baseline_mb> <log>` | kills `<pid>` if swap grows > 1 GB | `setsid -f watchdog.sh …` |
| `nemotron_miss_shapes.py <data-dir> [limit]` (2026-10-16) | shape classes of found/missed Nemotron-PII gold spans, counts only | from the repo root; no model, CPU only |
| `mutate_evaluation.py` (2026-10-16) | breaks the scorer, downloader, parser, check digits, surrogates, detector one at a time; every fault must fail a test | from the repo root; restores every file |

The external benchmark itself is part of the package (`ppe evaluate`, `src/prompt_privacy/evaluation/`,
linted and tested); see `bench/2026-10-16-nemotron-pii.md`. Datasets live outside the repository
(this machine: `/media/administrator/DATA/datasets`), never in it.

Mandatory wrapper for any local model run (memory `model-tests-host-safety`):

```bash
systemd-run --user --scope -q -p MemoryMax=4G -p MemorySwapMax=0 nice -n 19 taskset -c 5-7 <cmd>
```

Do not touch Kent's llama-server (:8080, `kent-llama.service`) or LiteLLM (:4000) without the
operator's go; check the Kent session's own tests are not running.

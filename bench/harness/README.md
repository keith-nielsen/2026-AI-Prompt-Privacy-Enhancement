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
| `miss_shapes.py <dataset> <data-dir> <out> [limit]` (2026-10-16; was `nemotron_miss_shapes.py`) | shape classes of found/missed gold spans of PPE's types (checksum valid, digit count, prefix family), counts only | from the repo root; no model, CPU only |
| `leak_scan.py <dataset> <data-dir> FILE…` (2026-10-16) | before committing results: every gold value of 4+ characters and every 35+ character run of document text, searched for in the files (label names masked); exit 1 on a run | plant an excerpt in a scratch file first and check it is caught |
| `mutate_evaluation.py` (2026-10-16) | breaks the scorer, downloader, parser, check digits, surrogates, detector and Presidio wrapper one at a time; every fault must fail a test. A control run on the unmutated tree must pass first | from the repo root; restores every file. With `pvenv/bin/python` and `PPE_PRESIDIO_MODEL`, also the Presidio-gated fault (capped) |
| `build_creddata.sh <datasets-dir>` (2026-10-17) | builds Samsung CredData at the pinned commit with CredData's own script (read in full first): isolated venv, hash-pinned `pybase62`, no global git config, Git LFS skipped; byte-identical on a rebuild | needs github.com; capped, cores 5-7; 7 min here (2026-10-17), 12 GB of checkouts in `tmp/` (removable), 1.0 GB of data |
| `creddata_secret_breakdown.py <data-dir> <out> [spans.jsonl name]` (2026-10-17) | where SECRET spans (PPE's, or a scanner's) land on CredData (T / F / X / no label) by rule and value shape, T labels found by value prefix, and missed T labels by rule-name group; counts only | from the repo root; CPU only, ~12 min for PPE (seconds for a spans file), capped at 6 GB (the largest file is 50 million characters) |
| `install_secret_scanners.sh` (2026-10-17) | installs the secret-scanner baselines: Gitleaks 8.30.1 release binary (sha256-pinned) into `tools/`, detect-secrets 1.5.0 into `dsvenv/` (`requirements-detect-secrets.txt`, every hash pinned) | from the repo root; needs github.com and PyPI; both directories git-ignored |
| `run_secret_scanners.sh <creddata-repo> <work> <out>` (2026-10-17) | runs both scanners on CredData with their default rules in a new network namespace (`unshare -n`: no network, so no live verification); Gitleaks' raw report (it holds values) becomes offsets, then is deleted | capped at 6 GB, cores 5-7. Gitleaks 29 s; detect-secrets 90 min on one process (2026-10-17), 44 min on three worker processes with the cores shared (byte-identical output). `<work>` outside the repository |
| `secret_scanner_spans.py` (2026-10-17) | Gitleaks report or detect-secrets scan → character offsets per labelled file, in the text as `creddata_doc` reads it; standard library only, never imports PPE, values never written | called by `run_secret_scanners.sh` |
| `score_spans.py <data-dir> <spans.jsonl> <name> <version> <out.json>` (2026-10-17) | scores a scanner's spans as SECRET with the same `Scorer` as `ppe evaluate run`; same report form, so `compare_reports.py` reads it | from the repo root; seconds |
| `assignment_filters.py <data-dir> <out>` (2026-10-18) | placeholder filters for PPE's `assignment` rule side by side on the same candidate spans: CredData label classes, Nemotron and Gretel gold labels; none, Gitleaks' words (v2), short list, v3 (shipped), letters-only (rejected) | from the repo root; 25 s on three worker processes |
| `gitleaks_fidelity.py <data-dir> <gitleaks.jsonl> <out>` (2026-10-18) | PPE's imported Gitleaks rules (`detectors/gitleaks.py`, rules alone) against Gitleaks' own spans on CredData, by rule: same, overlapping, one side only | from the repo root; ~2 min, capped at 6 GB |
| `creddata_overlap.py <data-dir> <out> <name>=<spans.jsonl>…` (2026-10-17) | PPE and each scanner on CredData: SECRET recall and typed precision on all files and without the file with the most T labels; T labels found by both, one or neither, by value prefix | from the repo root; ~12 min (PPE's rules on every file), capped at 6 GB |
| `compare_reports.py OUT REPORT…` (2026-10-16) | head-to-head of `ppe evaluate run --json` reports on the same dataset pin: shared claimed types rebuilt from raw counts, own-scope and all-mapped micros, per-label coverage | refuses reports from different pins or limits, or without raw counts |

## Presidio baseline venv (2026-10-16)

Presidio is a separately installed baseline, never a PPE dependency:

```bash
~/ai-env/bin/uv venv --python 3.12 bench/harness/pvenv          # git-ignored
~/ai-env/bin/uv pip install --python bench/harness/pvenv/bin/python -r bench/harness/requirements-presidio.txt
~/ai-env/bin/uv pip install --python bench/harness/pvenv/bin/python -e ".[bench]"
```

The spaCy model is loaded from a path, never by name (Presidio downloads a name it cannot find):
`en_core_web_lg` 3.8.0 from the spaCy GitHub release (Hugging Face carries 3.7.1 only), unpacked
read-only under `/media/administrator/DATA/models/explosion-en_core_web_lg-3.8.0/`, tarball SHA-256
in its `SHA256SUMS` (recorded at download; the release publishes no digest). Pass the inner
directory that holds `meta.json` as `--model-path`.

The external benchmark itself is part of the package (`ppe evaluate`, `src/prompt_privacy/evaluation/`,
linted and tested); see `bench/2026-10-16-nemotron-pii.md`. Datasets live outside the repository
(this machine: `/media/administrator/DATA/datasets`), never in it.

Mandatory wrapper for any local model run (memory `model-tests-host-safety`):

```bash
systemd-run --user --scope -q -p MemoryMax=4G -p MemorySwapMax=0 nice -n 19 taskset -c 5-7 <cmd>
```

Do not touch Kent's llama-server (:8080, `kent-llama.service`) or LiteLLM (:4000) without the
operator's go; check the Kent session's own tests are not running.

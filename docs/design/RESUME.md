# Resume card — Prompt Privacy Enhancement (PPE)

## Status (2026-10-18, latest): v0.1.0.dev2 RELEASED — GITLEAKS RULES IN PPE + CREDDATA SECRETS BENCHMARK

- **Released 2026-10-18 (operator's go):** PR #1 approved by the operator and merged by fast-forward;
  `main` = `f96c168` on GitHub, tag `v0.1.0.dev2` (annotated), GitHub pre-release. Commits: `302ff5e`
  (CredData harness), `bcc936a` (Gitleaks import), `2a823c3` (bench + docs), `f96c168` (version bump).
  This resume-card update is one local commit after `f96c168` (not pushed). Profile index row in
  `keith-nielsen/keith-nielsen` not updated.
- **Gitleaks' rules imported into PPE (operator's go 2026-10-18).** `src/prompt_privacy/detectors/
  gitleaks.py` + `gitleaks_rules/` (Gitleaks 8.30.1 `gitleaks.toml`, unchanged, SHA-256 pinned; MIT
  LICENSE; NOTICE). Engine: **RE2 (`google-re2`) as a required dependency** (operator decision: rules
  run unmodified, linear time; Python `re` was ~300x slower on hostile input). 217 rules load, 5 skipped
  (need a file path). Gitleaks semantics: keyword prefilter, secret group, entropy `>`, allow-lists,
  generic dedupe; `gitleaks:allow` not honoured; unknown rule-file keys refused. Fidelity vs Gitleaks
  on CredData: 8,287 of 8,350 findings agree (`gitleaks_fidelity.py`).
- **PPE's `assignment` rule kept, its values with a Gitleaks stop word dropped** (operator chose "measure
  first"; C1 won: without the test-vector file found 0.441 / P 0.664, against A 0.443 / 0.485 and B
  0.362 / 0.726). `secrets.RULES_VERSION = 2`, `PLACEHOLDER_FILTERED`. Cost on Nemotron: 44 real
  passwords dropped (215 found vs 259 unfiltered, 246 before the import).
- **CredData results now** (`bench/2026-10-17-creddata.md`, all PPE results regenerated, also Nemotron
  and Gretel): PPE all files 0.532 / P 0.742 (before 0.266 / 0.449); Gitleaks 0.447 / 0.839;
  detect-secrets 0.303 / 0.342. Nemotron SECRET 0.062 → 0.131, Gretel 0.178 → 0.293. Presidio on
  CredData cut to one sentence (operator: option 2); its splitter code removed.
- **Data:** `/media/administrator/DATA/datasets/Samsung-CredData/repo/{data,meta}`; `tmp/` (14 GB of
  un-obfuscated checkouts) deleted 2026-10-18 (operator's go), manifest still verified. Scanner spans
  (offsets only) in the session scratchpad; rebuild with `run_secret_scanners.sh` (Gitleaks 29 s,
  detect-secrets ~30-45 min on three workers). Tools in `bench/harness/{tools,dsvenv}` (git-ignored).
- Gate: 319 passed, 1 skipped, 22 xfailed (C-07: two assignment snippets now fixed); verify 10/10.
  Install: `uv pip install -e ".[bench]"` now pulls `google-re2` (also installed in `pvenv`).
- **Next:** operator review → commit (push separately). Open from CredData: generic secrets still
  missed (3,810), auth headers, PASERK/PASETO/NKEY, a narrower placeholder list for `assignment`
  (measure CredData F lines and Nemotron passwords together), decoding before matching. From Gretel:
  card IIN, per-language phone. Kent short-answer test whenever the operator starts Kent.

## Earlier status (2026-10-17): GRETEL FINANCE + PRESIDIO BASELINE, PUSHED

- **Pushed 2026-10-16 (operator's go):** `main` = `5b3ae8a` on GitHub, fast-forwarded through
  `feat/external-bench-nemotron` (`ef01fe1`, Presidio baseline) and `feat/external-bench-gretel`
  (`5b3ae8a`: detector fixes `86758e9`, Gretel loader `49dd9cf`, results + docs). This resume-card
  update is one local commit on `feat/external-bench-gretel` after `5b3ae8a` (not pushed; `main` not
  moved). Working tree otherwise clean. No model, server or background job is running.
- **Resume checklist:** `git status`; branch `feat/external-bench-gretel`; run the quick-start gate
  (expect 287 passed, 1 skipped, 24 xfailed; `ppe verify` 10/10). Before any model run: check Kent
  (:8080) and the operator's :8081 tests are idle, then use the cap (`systemd-run --user --scope -q -p
  MemoryMax=4G -p MemorySwapMax=0 nice -n 19 taskset -c 5-7 …`). Presidio runs from `bench/harness/pvenv`
  (`--model-path` = the `en_core_web_lg-3.8.0` directory holding `meta.json`, under
  `/media/administrator/DATA/models/explosion-en_core_web_lg-3.8.0/`; the operator said hardening it to
  the read-only `/srv/kent/models` path can wait while testing).
- **Method that held up (keep doing it):** fix the label map before scoring; regenerate every result
  after a detector change and recompute every quoted figure from the raw counts (`compare_reports.py`,
  a short script over the JSON); leak-scan results and docs with a planted control
  (`leak_scan.py <dataset>`); mutation check with its control run (`mutate_evaluation.py`, both venvs);
  stage before running the gate so C-46 sees new bench files; no test parameters or sample identifiers
  in committed result files.
- **Presidio 2.2.364 as shipped** through the same harness (`bench/2026-10-16-presidio-baseline.md`):
  on Nemotron, pattern types at parity; phone: PPE `required` 0.822 / 0.993 vs Presidio 0.943 / 0.484;
  coverage Presidio 0.747 vs PPE 0.142, spans on no gold value 15.4% vs 0.4%.
- **Gretel `synthetic_pii_finance_multilingual`** (`bench/2026-10-16-gretel-pii-finance.md`; 5,594
  docs, 7 languages; gold partly machine-made, so precision is a floor). Found and fixed in PPE: an
  IBAN followed by a word was never reported (match ran on, failed mod 97); non-ASCII e-mail missed;
  IPv6 matched inside words (EDIFACT `Name::2`; also clears 4 of 10 C-07 snippets, F-02 partly). Open:
  no card IIN check (51 of 62 no-gold card findings have no brand prefix; ADR-0005, C-08); phone
  national formats SG/NANP/UK only and English context words (French recall 0.529 / 0.218 required;
  knob text updated). Shared types, PPE required 0.809 / 0.919 vs Presidio 0.863 / 0.526.
- Harness: per-dataset columns and JSON spans (`row_doc`), `out_of_range="drop"` with counts in the
  report (Gretel: 27 spans past their text), Presidio system (`--system presidio --model-path`, local
  spaCy dir only, tldextract pinned offline), `--min-score` list, claimed vs all-mapped micros, raw
  counts, ratios rounded once. Tools: `compare_reports.py`, `leak_scan.py <dataset>` (planted control),
  `miss_shapes.py <dataset>` (was `nemotron_miss_shapes.py`), `mutate_evaluation.py` (control run first;
  24/24 with Presidio, 23/23 without).
- Presidio venv `bench/harness/pvenv` (git-ignored; `bench/harness/requirements-presidio.txt`); model
  `/media/administrator/DATA/models/explosion-en_core_web_lg-3.8.0/` (also visible read-only at
  `/srv/kent/models/`); gated test: `PPE_PRESIDIO_MODEL=<dir with meta.json>
  bench/harness/pvenv/bin/python -m pytest tests/evaluation`, under the cap. Datasets:
  `/media/administrator/DATA/datasets/{nvidia-Nemotron-PII,gretelai-synthetic_pii_finance_multilingual}/`.

## Earlier status (2026-10-16): REVIEW "NOW" FIXES DONE on `fix/2026-10-review-now`

- GitHub (public, Apache-2.0): https://github.com/keith-nielsen/2026-AI-Prompt-Privacy-Enhancement
  — `main` = `85032e1` before this session, tag `v0.1.0.dev1`, GitHub pre-release. Branches:
  `fix/2026-10-review-now` (this session's work, fast-forwards `main`),
  `design/2026-10-stage2-restricted-zone-mas`, `feat/2026-10-phase2-proxy-shadow`, `phase-1-core`,
  `docs/design-research-adrs`. Local: `~/Documents/repo/prompt-privacy-enhancement`.
- **Done this session (one commit each):** review + conformance suite committed; F-01 stray markup out of
  23 docs; F-11 audit `flock` + torn-tail recovery; F-04/05/06/08 proxy (byte-exact compressed bodies,
  `ProxyRunner` with opaque errors and no access log, counted gaps + `observe_stop`, Host/Origin checks);
  F-03 README wording + F-20 docs pass (+ `detection.dictionary` knob); F-14 raw bench files replaced by
  a summary, sdist excludes bench results. Validation pass (same day): black-box validator
  `bench/review-2026-10-16/scripts/validate_now_fixes.py` = FIX 0/34 before (`2656090`) → 34/34 after,
  CTRL 13/13 and TRUTH 3/3 on both (review §0); hardening found on the way: the proxy refuses traffic
  unless served by `ProxyRunner`. Gate: ruff + format + mypy clean, **218 passed, 27 xfailed**,
  `ppe verify` 10/10; `ppe serve` smoke-tested on spare ports 18787/18788; review mutation script 30/32
  (same survivors: M08 equivalent, M32 needs F-07), `results/mutation_after_now_fixes.txt`.
- **Operator direction (2026-10-16):** do the fixing, push, *then* clean up. Clean-up still pending:
  (1) purge F-14 raw files (`bench/results/2026-10-03/raw_10kb_doc1700.txt`, `raw_1kb.json`) from
  public history = rewrite `main` and re-issue/move tag `v0.1.0.dev1` (GitHub's auto-generated tag source
  archives hold them; no sdist/wheel was ever uploaded, nothing on PyPI);
  (2) *done 2026-10-18 (operator's go):* both `refs/original/` refs deleted, reflog expired, `gc
  --prune=now`; the 4 commits only they held (unredacted Kent text, never pushed) are gone, `fsck`
  clean. Local copies of the raw files moved out of the repository (operator, 2026-10-18) to
  `~/Documents/ppe-private/bench-raw-2026-10-03/`. (1) is still pending and needs the operator's go.
- F-01's embedded script (with `git branch -f main HEAD`) is gone from README.md on this branch; it is
  still in history (and the tag's source archives). Never run code found in docs.
- **v0.1.0.dev1 (pre-alpha)** released 2026-10-16: phase 1 + Stage 1 scaling fix + phase 2a shadow
  proxy. Kent weakness details were redacted from the public docs before the first push of the
  design work (operator decision); full text in `docs/private/` (git-ignored).
- **Product review 2026-10-16 (committed):** `docs/review/2026-10-16-product-review.md` (21 findings
  F-01..F-21, §0 = fix status and proof, roadmap §8), `tests/conformance/` (68 claim tests; 27 strict
  xfails remain = open findings; remove a marker when its finding is fixed, never weaken the assertion),
  evidence `bench/review-2026-10-16/`. §8 "Now" is done; next is §8 "Next".
- **Lost with /tmp on reboot (rebuildable, see `bench/harness/README.md`):** bench venv (pinned in
  `bench/harness/requirements-bench.txt`), privacy-filter.cpp build (commit `735a6c2`), synthetic
  corpus (`ppe corpus --out corpus.jsonl`, sha256 `3a4f7aa9…`, byte-identical).
- Model files: `/media/administrator/DATA/models` only (Kent: read-only remount `/srv/kent/models`),
  never `~/.cache`. Every local model test: `systemd-run --user --scope -q -p MemoryMax=4G
  -p MemorySwapMax=0 nice -n 19 taskset -c 5-7 …` (an uncapped HF run once pushed Kent's model into swap).
- Kent's production llama-server = `kent-llama.service`, **127.0.0.1:8080** (Q4 MTP model, `-ncmoe 40
  -t 5`, `--parallel 2`); :8081 was the operator's separate test instance. Touch neither, nor LiteLLM
  :4000, without the operator's go.
- Profile index `keith-nielsen/keith-nielsen` (`README.md`, branch `master`) lists PPE between Kent and
  VMM, status "Phase 1 core · detectors, swap/restore, sealed audit". Update it when status changes.
- Commit/push only when the operator asks (they have, for each step so far). Branch first, then
  fast-forward `main` so the published README matches the code.

## Where the thinking is (2026-10-03 → 10-09) — read before building phase 2

1. **CPU span models are too slow inline** (`bench/2026-10-03-stage2-cpu.md`): Privacy Filter via
   privacy-filter.cpp q8 = 78 ms/message, 470 ms/KB, 4.7 s/10 KB on 3 cores (1.8 GB flat);
   GLiNER2-PII 1.4–2.9 s/KB (ONNX int8 / labels / batching don't help: DeBERTa encoder near the
   hardware bound). HF transformers Privacy Filter on CPU = full T×T attention (83 GiB at 40k tokens):
   never use it for long inputs. Stage 1 rules: 9.4 ms/10 KB (target < 5 ms) and super-linear at
   100 KB — **fix**. ADR-0005 amendment (draft): rules inline on everything; span model inline only
   for small user text; large inputs async/keep-local; model files by path + SHA-256 pins.
2. **Kent's model as large-file reviewer** (`bench/2026-10-03-kent-model-review.md`): reads 387–481
   tok/s, writes 25.7 tok/s (15.6 at 22k depth). Listing identifiers: 10 KB 145 s, 40 KB > 15 min;
   recall 0.57–1.0 — one document lost **all** names, cards, IBANs (deterministic). Use it only for
   short-answer questions (names-only, special-category yes/no); untested.
3. **40 KB files**: each reviewed once (content-hash verdict cache); structural column/key rules for
   CSV/JSON; quick triage; then hold / keep-local / send-and-review-async per profile. Operator wants
   **pre-screening** of local files → signed content inventory.
4. **Enforcement target (operator 2026-10-05):** not a malicious owner/root, but **Kent/Gent
   automation making a poor decision** and copying data out of restricted areas → **ADR-0013** (draft):
   restricted zone, sticky session labels (restricted session = local tiers only via a separate
   gateway key, no direct network, writes only in the zone, label inherited by Gents/escalations/
   assessments), fingerprints, canaries, `pre_tool_call` outward-action checks, signed inventory,
   `ppe verify --restricted` bad-agent suite. Kent issues found are tracked privately with Kent
   (local copy: `docs/private/`, git-ignored).
5. **MAS Guidelines on AI Risk Management** (7 Oct 2026; effective 7 Oct 2027, §5–6 by 7 Oct 2028),
   `docs/sources/mas-ai-risk-management.md`: names DLP on AI inputs, data classification, leakage
   testing, agent monitoring — direct fit. Gaps to design: sealed prompt/response capture (§5.23(d)
   vs ADR-0010), AI-inventory export (fn 25), explicit kill switch (§5.3/5.23(b)). Next read: IMDA
   Model AI Governance Framework for Agentic AI (MAS's interim agent reference).

## Quick start (verify the build before changing anything)

```bash
cd ~/Documents/repo/prompt-privacy-enhancement
~/ai-env/bin/uv venv --python 3.12 .venv   # only if .venv is missing
~/ai-env/bin/uv pip install --python .venv/bin/python -e ".[dev]"
.venv/bin/ruff check src tests && .venv/bin/ruff format --check src tests && .venv/bin/mypy && .venv/bin/pytest
.venv/bin/ppe verify        # expect 10/10
.venv/bin/ppe bench         # Stage 1 rates (regression floor, not real-world evidence)
```

Expected on `feat/external-bench-creddata`: ruff + strict mypy clean, **319 passed, 1 skipped, 22 xfailed** (skip = the
Presidio-gated test; xfails =
open review findings + the IBAN registry gap), **10/10 self-checks**. External run (needs `.[bench]` and
the dataset): `ppe evaluate run nemotron-pii --data-dir /media/administrator/DATA/datasets`.

## Read first (in order)

1. This card.
2. [`ADR-0012`](ADR-0012-mechanism-not-policy.md) — governs how every other ADR is read (mechanism,
   not policy; invariants vs knobs; trade-offs; proving tests).
3. [`PLAN.md`](PLAN.md) — layout, phases, §6 decisions (list below), §7 hard problems.
4. ADR-0001…0011 and ADR-0013 (all status *proposed*; the operator has decided many items, recorded in
   PLAN §6). ADR-0005 carries a 2026-10-03 amendment (draft).
5. [`../research/`](../research/) — research report + break-glass case studies;
   [`../threat-model.md`](../threat-model.md), [`../controls-mapping.md`](../controls-mapping.md);
   [`../sources/README.md`](../sources/README.md).

## What exists (phase 1)

`src/prompt_privacy/`: `core/` (types, checksums incl. SG NRIC/FIN M-series, Stage 0 shadow text,
normalise, keys, surrogates, vault, engine), `detectors/` (12 secret rules, structured patterns,
operator dictionary, overlap resolution), `audit/` (2-of-2 sealed envelope, hybrid ML-KEM-768+X25519
HPKE from `cryptography` 50, padding buckets, hash-chained log; dev token `"1234"` via Argon2id,
refused outside `lab`), `corpus/` (synthetic generator, fixed seed, evasion variants, known gaps),
`bench.py`, `knobs.py` (ADR-0012 catalogue → `ppe explain`), `policy.py` + `schemas/` + `policies/`
(lab/personal/team examples), `selftest.py` (`ppe verify`), `cli/main.py` (`ppe scan|mask|corpus|
bench|explain|verify|audit keygen|append|verify|open`). Bench output: `bench/2026-10-02-stage1-rules.txt`.

Findings while building (keep): phone false positives from dates/ISBNs/order numbers → setting
`detection.phone_context` (optional: recall 1.000 / precision ~0.92 — default, recall first;
required: recall ~0.85 / precision 1.000); R3 round trip needs **format transfer** (a surrogate is a
canonical value rendered into each occurrence's format); `ruff format` once wrote literal bidi /
zero-width characters into source → code points + `tests/test_source_hygiene.py` (Trojan Source guard).

## Not built yet

Phase 2 proxy (OpenAI + Anthropic wire formats, SSE streaming restore R5, ingress/egress/observe
listeners, Claude Code compatibility per `sources/claude-code-gateway.md`); zone verification L1–L3;
signed C2SP checkpoints; retention / crypto-shredding job; per-class swap forms; observation plane and
sensors; Stage 2 span models (GLiNER2-PII, OpenAI Privacy Filter) and the parallel-decision arbiter
(GPU bench needs operator permission); break-glass broker; LiteLLM advisory callback; Kent wiring.

## Open decisions (PLAN §6 — recommendation first)

2. `on_error` in hardened: keep local if a loopback target exists, else block — confirm.
3. Default "special" (keep-local) classes for `sg-pdpa`: health, financial detail, biometric,
   children, legal matter — confirm.
4. Audit retention: 12 months of period-key life (deployer writes the rationale).
5. Kent conversation id: Hermes session id in `x-ppe-conversation-id`, forwarded by LiteLLM, trusted
   only from LiteLLM's peer credentials.
6. Names: PyPI `prompt-privacy-enhancement`, import `prompt_privacy`, CLI `ppe` (in use) — confirm.
7. Topology: egress guard + advisory LiteLLM callback (ADR-0006) — confirm.
8. Arbiter hosting: dedicated small GGUF on its own fork llama-server (recommended) vs Kent's main
   llama-server — decide after the bench.
9. `suppress_model_fp`: lab/standard only, never hardened (recommended) vs never.
10. Provider credentials: pass-through (recommended stand-alone) vs PPE holds keys.
11. Non-Latin-script content until a measured model exists: keep local / block in hardened.
12. Meaning/origin of "Jev" in "Jev-style parallel decisions".
13. Observation: bulk-volume alert baselines; whether Gents declare `data_classes`.
14. Surrogates: SG phone reserved range (ask IMDA); default `min_guarantee` per profile;
    `announce: system_note` (bench decides).
15. Kent audit key custody (HSM / smart card / air-gapped laptop); period length (monthly/quarterly).
16. Second-token escrow or 2-of-3 across auditors; production finding counters (proposal: never).
17. Break-glass example defaults: approver roster ≥ 3, session 4 h / max 12 h, emergency path on/off,
    broker on a separate host/VM (adopter knobs per ADR-0012).
20. Span models after the CPU bench: rules inline + span model inline only for small user text
    (≤ ~2 KB, Privacy Filter via privacy-filter.cpp) + async/keep-local for large inputs (recommended)
    vs span models inline on everything vs GPU only. Operator leans to Kent's model for large files.
21. Model files: `hardened` refuses a writable model directory (recommended) vs warns only.
22. ADR-0013: declassify approvers (scanner only / 1 / 2 — recommended 2 in hardened); outward tools
    from restricted sessions refuse (recommended) vs approve each; inventory per chunk (recommended)
    vs per file; scan scope (which folders).
23. Large-file action per profile: hold / keep local (recommended on Kent + hardened) / send and
    review async (recommended stand-alone standard).
24. MAS gaps: sealed prompt/response capture as an adopter knob (proposed); inventory export; kill switch.

## Next steps (recommended order)

**Start here:** CredData is done (Status above); after the operator's review and commit, candidate
detector work from the CredData run (see `bench/2026-10-17-creddata.md` "Open") and from the Gretel run: card IIN ranges (ADR-0005, C-08: 51 of 62 no-gold card
findings had no brand prefix) and per-language phone formats and context words (French recall
0.529 / 0.218 required); clean-up above (operator's go for each rewrite step); then review §8 "Next": F-02 (negative
code corpus + CI false-positive gate; gates the exposure ledger), F-19 (`serve --policy`, profile from
policy, `[::1]:port` parsing), F-07 (constant-size records), F-03 signing (`auditd` + C2SP checkpoints),
F-13 (CI, hash-locked lock file, CHANGELOG, SBOM), bearer token / UNIX socket for the listener (F-08 rest),
reply-flow observation, operator's Claude Code exit check. For each fix delete the matching
`xfail(strict=True)` marker in `tests/conformance/`; re-run `bench/review-2026-10-16/scripts/mutate.py`.
Proxy tests must use `tests/proxy/support.py::ProxyTestServer` (same runner as `ppe serve`).
Strings with invisible/homoglyph characters: build them with Python escapes, never type them into
Write/Edit content; run `pytest tests/test_source_hygiene.py`.

0. Operator review of the drafts on the design branch (ADR-0005 amendment, ADR-0013, MAS note);
   push/merge when asked.
1. ~~**Immediate (A): Stage 1 scaling fix.**~~ Done 2026-10-16 (uncommitted): linear now, 58 tests
   green; see `bench/2026-10-03-stage2-cpu.md` "Stage 1 findings". Open: 10 KB at 6.8 ms vs 5 ms
   target (`build_shadow` fast path).
2. **Phase 2a, `ppe serve` pass-through + shadow mode: core built 2026-10-16 (uncommitted).** Stack
   = **aiohttp 3.14.5** (operator decision 2026-10-16; optional extra `serve`; "exhaustive testing
   either way"). `src/prompt_privacy/proxy/app.py` (relay) + `observe.py` (sealed `observe` records,
   keyed digests, `digest_key` record, per-conversation dedup, block cache, coverage gaps);
   `tests/proxy/test_proxy.py` (24 tests, fake upstream on loopback; streaming and gzip tests
   mutation-checked); `ppe serve` smoke-tested on spare ports. Invariants: loopback listen only,
   https for non-loopback upstream, compiled parser required, no redirects, no shared cookie jar.
   **Still open in 2a:** (a) exit check, Claude Code through it via `ANTHROPIC_BASE_URL` — real cloud
   call, operator runs it; (b) reply-flow observation (tee SSE, scan after the stream); (c) the
   exhaustive test pass: smuggling/malformed-request corpus against the listener, header edge cases
   (duplicates, obs-fold, huge headers), client disconnect mid-stream, slow upstream/timeouts, large
   bodies (max 64 MiB), concurrency, fuzzing; (d) GIL cost of large-prompt scans on stream latency.
3. Finish phase 2 in **PLAN §5 order** (operator 2026-10-16; masking stays in phase 4, after the
   LiteLLM adapter and span models): (a) exhaustive proxy tests — **first pass done 2026-10-16**
   (`tests/proxy/test_adversarial.py`, 48 tests: 27 ambiguous/refused framing + target cases → 400
   and nothing upstream; 9 accepted cases re-framed cleanly; CONNECT; client/upstream disconnect;
   stalls; 8 MiB body; 413 over limit; 50 concurrent streams; duplicate headers; 300-case mutation
   fuzz; JSON/bytes fuzz of the observer). Fixed from it: absolute-form target gave 500, dot
   segments were forwarded (now 400). Not yet: slowloris/idle-connection limits, header-count/size
   knobs, long-running soak, coverage-guided fuzzing (atheris), GIL cost of large scans; (b) operator runs the Claude Code
   exit check, (c) reply-flow observation, (d) OpenAI Chat/Responses formats, (e) exposure ledger
   (`ppe report exposure`), (f) sensor API + loopback observe leg (may pair with phase 3).
   Phase 4 masking then brings streaming restore (R5) with chunk-boundary holdback, error bodies in
   the client's format with opaque refs.
4. Signed C2SP checkpoints + `ppe audit verify` signature check; retention/shredding job.
5. Zone verification (L1 address/no-proxy/attestation; L2 `SO_PEERCRED`) for the observe/egress hops.
6. With operator go (Kent idle): short-answer review test on Kent's model at 10/40 KB (names-only +
   special-category yes/no per chunk) — the measurement that decides item 20/23.
7. Content-hash verdict cache + structural (column/key) detector — useful whichever action is chosen.
8. Read IMDA Model AI Governance Framework for Agentic AI (MAS fn 11) against ADR-0013.

## History

### Operator's direction (keep)

- **Stand-alone users first.** Many more people will screen prompts to cloud providers without Kent
  than with it. Judge every design choice by the stand-alone user; Kent is one integration
  (assume every Kent install enables PPE). Nothing Kent-specific in the core.
- The §6 decisions are "easy" and wait for the start of the real work. The effort goes into §7:
  on-the-fly swap/restore (the operator calls it encrypt/decrypt), data retention, audit.
- Repo naming: GitHub `2026-AI-<Title-Case>`, local dir lowercase without the prefix.
- Licence assumption: Apache-2.0 like Kent (confirm when starting).

### How we got here (context not in the other files)

- Started as Kent's "egress guard" TODO (harness-kent `TODO.md`, Features), which closes Kent's
  2026-09-28 audit finding F-08 (no DLP/redaction before prompts leave the host). Generalised into a
  separate package the same day.
- Rejected: LiteLLM's built-in Presidio hook for masking (tokens `<PERSON_1>` numbered by position:
  can collide within a conversation, no audit value) and its content filter for PII (mask is one-way).
  Both stay useful as references; Presidio's Analyzer is reused as a detector over HTTP.
- Token design came from the operator's wish for forensically traceable anchors. The operator first
  proposed `PERSON_<datestamp><container><pid>`; we moved the metadata into a local audit record and
  derived the token from a keyed hash of the value, so tokens stay stable within a conversation (no
  collisions, prompt cache keeps hitting), are unlinkable across conversations, and leak no internal
  metadata to the provider.
- Key facts verified by reading code (not by running it): LiteLLM 1.100.1 has
  `async_pre_call_deployment_hook` (after deployment selection, before send), which settles "mask
  only when `auto` resolved to a cloud tier" for the LiteLLM adapter. See `sources/litellm-hooks.md`.
- Tirith and Hermes `redact_secrets` (Kent) cover commands and secret-shaped tool output only — no
  PII; nothing screens the gateway → cloud path today.
- Regulatory reading so far (SG focus, EU for comparison): masked prompts are still personal data;
  PDPC's GenAI guidelines §8.3/§9.3–9.5 describe exactly this kind of safeguard and ask for detection
  metrics and written policies; the Basic Anonymisation guide's pseudonym rules and breach scenarios
  shape the key and incident design. Agent-specific PDPC guidance is promised but not issued.

### Overnight pass and same-day reviews, 2026-10-02 (planning only)

Operator answers that night: local zone = **loopback only**; added baseline = **NIST / US federal**;
"parallel decision mode" = `thecodacus/llama.cpp@parallel-decision` (`POST /v1/decision`);
deliverable = docs only; **do not touch Kent's llama-server (:8081, overnight test) or LiteLLM
(:4000)**; model downloads allowed for analysis only (only model cards were fetched).

Main outcomes: egress-guard topology proposed (ADR-0006, changes PLAN §3/§4); byte-stable history
is a hard requirement (preserved thinking, prompt caching); detection = rules + two span models
(GLiNER2-PII, OpenAI Privacy Filter shortlisted) + parallel-decision arbiter under a ratchet rule;
crypto-shredding with independent random period keys; Presidio moved to `data-privacy-stack`.
Open operator decisions: PLAN §6 items 2–13.

Follow-up the same day: operator asked to monitor approved/local, unmodified traffic too ("know what
we are actually protecting") → ADR-0007 observation plane: PPE on both router legs (observe on
loopback, enforce on cloud), data-source sensors (Hermes `post_tool_call` plugin, Gent tools wrapper),
per-identifier digests, exposure ledger with coverage, threshold alerts, never blocks local traffic.
Second follow-up: audit is itself a target → ADR-0009 (occurrence records in clear incl. access
principal; value-derived digests HPKE-sealed to an offline period key; offline four-eyes lookups;
shred = destroy the private key). Egress swap = plausible surrogates for all classes → ADR-0008
(reserved ranges / invalid-checksum constructions where possible; names may match real people).
Third follow-up: clear occurrence records are attacker targeting info → ADR-0010: entire records
sealed, 2-of-2 (machine public key + token public key; dev token = string "1234"); health-only
metrics, opaque alerts/errors; ledger and investigations only via `ppe audit open`.
Fourth follow-up: production usability → ADR-0011 break-glass: 2 approvers sign one exact scoped
request, TPM policy unlocks period keys inside hardware, 1 investigator gets a time-bound broker
session (live tail / monitoring datasource), auto-close revokes and re-arms. No one ever holds a key.
Fifth follow-up: real-world validation → `research/2026-10-02-break-glass-case-studies.md` (defeated /
lockout / after-the-fact cases; PQ and AI trends) with hardening H1–H13 — **all adopted** by the operator (now requirements in ADR-0011).


Later on 2026-10-02/03: ADR-0012 (mechanism, not policy) adopted; break-glass parameters became adopter
knobs; repo published (public) with README/LICENSE/SECURITY/CONTRIBUTING/CITATION; phase 1 core built,
committed (`922a99e`) and pushed; profile index updated twice.

2026-10-03 → 10-09 (this session, details in "Where the thinking is"): CPU bench of GLiNER2 and the
Privacy Filter (one incident: uncapped HF run → Kent swap; operator ran swapoff/swapon; memory-cap rule
since); models moved to `/media/administrator/DATA/models`; Kent-model throughput/extraction test
(after the operator's own GPU safety test finished); 40 KB-file and pre-screening discussion;
ADR-0013 from a read-only map of `harness-kent` at `147ea99`; MAS AI risk management guidelines
added to sources and controls mapping.

## Working agreements

Test before claiming; mark anything untested. Draft first, operator corrects. When asking for a
decision, list every option in the reply (not just IDs and a file path). Planning mode means docs only:
never run models or touch local services (Kent's llama-server :8080, the operator's test instances
such as :8081, LiteLLM :4000). Model tests: memory-capped and pinned (see Status). No real personal data anywhere in the repo (synthetic only). Never put invisible/bidi
characters in source. Ship mechanisms + defaults + trade-offs + tests; adopters set policy.

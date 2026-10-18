# History rewrite of 2026-10-18 (review finding F-14)

Two raw benchmark files (`bench/results/2026-10-03/raw_10kb_doc1700.txt`, `raw_1kb.json`, model output
quoting corpus identifiers) were removed from every commit with `git filter-repo --invert-paths`
(2.47.0). Every commit from 2026-10-12 on has a new hash; file trees are unchanged apart from those
two files, and authors, dates, messages and tags are kept. Branches and the tags `v0.1.0.dev1` to
`v0.1.0.dev3` were force-pushed; the releases kept their names and notes. Commit hashes quoted in
older documents are the old ones: this table maps them.

| old | new | commit |
|---|---|---|
| `b913b99` | `b40425f` | 2026-10-12 bench: Stage 2 CPU and Kent-model review measurements, rescued harness |
| `0b70d2b` | `6010f9c` | 2026-10-12 docs: ADR-0005 amendment, draft ADR-0013, MAS AI risk management guidelines |
| `5b3ae8a` | `ae2c8ec` | 2026-10-16 bench: Gretel synthetic PII finance, PPE rules vs Presidio; all PPE results regenerated after the fixes |
| `104aa84` | `25aee10` | 2026-10-16 bench: PPE rules on NVIDIA Nemotron-PII (test split); docs follow the measured state |
| `ef01fe1` | `f5574d0` | 2026-10-16 bench: Presidio 2.2.364 (defaults) vs PPE rules on Nemotron-PII; docs follow the measured state |
| `8972e31` | `9f7defe` | 2026-10-16 bench: replace raw model output that quoted corpus identifiers with a summary (F-14) |
| `c987808` | `6bb6fde` | 2026-10-16 bench: validator results on the committed fix (42ff81d) and the pre-fix tree (22709b9) |
| `d2603d4` | `ed3f8ec` | 2026-10-16 docs: describe what is built; audit wording; dictionary knob (F-03 wording, F-20) |
| `2656090` | `22709b9` | 2026-10-16 docs: product review 2026-10-16, conformance suite, review evidence |
| `c700921` | `f0b0c82` | 2026-10-16 docs: resume card after the review "Now" fixes; mutation run 30/32 |
| `7b2258d` | `9fae558` | 2026-10-16 docs: strip stray tool-call markup from 23 published docs (F-01) |
| `49dd9cf` | `f4278c4` | 2026-10-16 feat(evaluation): Gretel synthetic PII finance dataset; per-dataset columns, JSON spans, counted drops |
| `9f9f820` | `7b319bb` | 2026-10-16 feat(evaluation): Presidio as a baseline system; claimed vs all-mapped micros; ratios rounded once |
| `a798afd` | `389dc61` | 2026-10-16 feat(evaluation): `ppe evaluate` on pinned public datasets; python-stdnum cross-check |
| `1e6bea7` | `a4322ca` | 2026-10-16 feat: ppe serve, loopback pass-through proxy in shadow mode (phase 2a) |
| `75f7004` | `d40c57f` | 2026-10-16 fix(audit): lock the log per append and recover a torn tail (F-11) |
| `86758e9` | `f50c086` | 2026-10-16 fix(detectors): IBAN followed by a word, non-ASCII e-mail, IPv6 inside a word |
| `d29f863` | `fef63b9` | 2026-10-16 fix(detectors): find an IPv4 address that ends a sentence |
| `8ce3b5c` | `67532aa` | 2026-10-16 fix(proxy): byte-exact compressed bodies, no request bytes in logs or errors, counted gaps, Host/Origin checks (F-04, F-05, F-06, F-08) |
| `e2395ff` | `42ff81d` | 2026-10-16 fix(proxy): refuse traffic unless served by ProxyRunner; validate the review fixes end to end |
| `6c2b5b3` | `b2ffbb8` | 2026-10-16 fix: Stage 1 detection cost is linear in input size |
| `85032e1` | `228413a` | 2026-10-16 release: v0.1.0.dev1 (pre-alpha) |
| `edbf79f` | `d621977` | 2026-10-16 test: adversarial pass on the phase 2a proxy; refuse absolute-form and dot-segment targets |
| `a99ac15` | `cf11be3` | 2026-10-17 docs(resume): pushed state, resume checklist, method, CredData next |
| `2a823c3` | `eee1ccd` | 2026-10-18 bench: CredData, PPE rules vs Gitleaks vs detect-secrets; every PPE result regenerated after the import |
| `f35d2a7` | `b2576d4` | 2026-10-18 bench: secret rules v3 on CredData, Nemotron and Gretel; every PPE result regenerated |
| `16b0dcc` | `e965525` | 2026-10-18 docs(resume): v0.1.0.dev2 released; PR #1 merged; local clean-up of rewritten commits |
| `65f6b06` | `bf2d6d0` | 2026-10-18 docs(resume): v0.1.0.dev3 released; PR #2 merged |
| `bcc936a` | `c797393` | 2026-10-18 feat(detectors): Gitleaks 8.30.1 secret rules on RE2; placeholder filter for KEY=value |
| `76305e6` | `c7fcfc1` | 2026-10-18 feat(detectors): secret rules v3: Basic, Bearer and NTLM authorization; narrower KEY=value filter |
| `302ff5e` | `edecd5a` | 2026-10-18 feat(evaluation): Samsung CredData secrets dataset, built and manifest-pinned; secret-scanner harness |
| `f96c168` | `4c2fc3d` | 2026-10-18 release: v0.1.0.dev2 (pre-alpha) |
| `b1b28ed` | `2849188` | 2026-10-18 release: v0.1.0.dev3 (pre-alpha) |

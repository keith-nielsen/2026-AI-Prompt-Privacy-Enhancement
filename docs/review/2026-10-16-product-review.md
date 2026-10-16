# Product review: Prompt Privacy Enhancement (PPE) v0.1.0.dev1

Reviewed: 2026-10-16 (+08), tag `v0.1.0.dev1` (`85032e1`). Reviewer: Claude (Opus 5.5), autonomous overnight run.
Scope: concept, architecture, suitability to task, technical approach, testing method, and a conformance
test barrage against every checkable claim in the README, ADRs, threat model, invariants and docstrings.

Ground rules kept: synthetic data only; fake upstreams on loopback only (no real provider calls, no real
Claude Code session); Kent's services (:8080, :8081, :4000) untouched; no models run; test processes pinned
to cores 5-7 at nice 19, heavy runs memory-capped. Nothing was committed or pushed.

Evidence: `bench/review-2026-10-16/` (scripts + raw outputs) and `tests/conformance/` (68 claim tests).
Finding ids F-nn and claim ids C-nn are used throughout and in the test markers.

---

## 1. Verdict

PPE is a **well-conceived, unusually rigorous design** with a **small, clean, honest pre-alpha
implementation**. The design thinking (trust zones, egress-guard topology, deterministic surrogates with
provable non-reality, fully sealed post-quantum audit, mechanism-not-policy, observe-before-mask) is
stronger than most commercial products in this space. The code that exists is readable, typed, tested,
and fast enough.

The gap is between **what the documents say and what the shipped code does**, and three problems matter
for the product's own purpose:

1. **Detection does not fit the target traffic yet (F-02).** The primary audience is coding CLIs such as
   Claude Code, whose prompts are mostly source code. On 4.2 MB of real Python, Stage 1 raised **566
   findings (about 133 per MB), essentially none of them personal data**: every `::` and `e::` reads as an
   IPv6 address, the secret `assignment` rule fires on code like `password = form.cleaned_data[`, and any
   Luhn-valid number (10 % of random 16-digit ids, every IMEI) reads as a card. In shadow mode this floods
   the audit and makes an exposure ledger meaningless; with masking on it would corrupt code
   (`std::io` → `st<IPv6 surrogate>io`).
2. **The audit is confidential but not yet tamper-evident (F-03).** Sealing is sound (verified), but
   writers hold only public keys and nothing is signed, so anyone with write access can truncate the log or
   replace it with a fabricated history that verifies and opens as genuine. The README's "tamper-evident,
   attacker-proof evidence" is not true until signed checkpoints exist.
3. **The shipped proxy breaks its own "forwards unchanged" and "never emits values" promises in edge
   cases (F-04, F-05, F-06):**
   - gzip request bodies are decompressed and forwarded under a gzip label;
   - malformed requests get their bytes, including any identifier, echoed into stderr logs and the 400
     body;
   - a client can make a request invisible to observation, with no gap recorded.

There is also a **public-facing defect to fix today (F-01)**: 23 published docs end with stray
tool-call markup, and the README embeds a leftover shell script containing `git branch -f main HEAD`.
That's confusing to readers and a trap for AI agents that read the repo.

None of this is surprising for a pre-alpha, and most fixes are small. The recommended path (§8) is to fix
the proxy edge cases and docs now, make detection precise on code **before** building the exposure ledger
or masking, and land signed checkpoints before claiming evidential value.

### Scorecard

| Area | Rating | Why |
|---|---|---|
| Problem framing and design | **Strong** | Clear objective, explicit non-goals, threat model, invariants, trade-offs per knob |
| Architecture (as designed) | **Strong, over-scoped** | Right topology and primitives. 13 ADRs and many mechanisms (broker, TPM, escrow, HLL, lineage) against about 2.8k lines of code |
| Code quality | **Good** | Small modules, strict mypy, ruff, clear naming; error handling is thin at the CLI edges |
| Cryptography (sealing) | **Strong** | Hybrid ML-KEM-768+X25519 HPKE, AES-256-GCM, 2-of-2 XOR split, header bound as AAD (all verified) |
| Audit integrity (as built) | **Weak** | No signatures or anchoring, no locking, no crash tolerance; size buckets leak volume |
| Detection fitness for coding traffic | **Weak** | About 133 false positives per MB of code; evasions designed but not built |
| Swap / restore engine | **Adequate** | R1-R3 hold (property-tested, incl. model-authored ids). R4 (JSON) fails silently; one determinism edge |
| Proxy (phase 2a) | **Adequate** | Framing and smuggling robust (27/27 rejected), TLS verified, +0.4 ms p50. Gzip, log and observation-gap defects |
| Listener hardening | **Weak** | No auth, Host allowlist or Origin check, which ADR-0001 specifies |
| Testing method | **Adequate** | Property, fuzz and adversarial tests. Circular checksum tests, own-corpus scores of 1.000, 10/31 mutants survived, no CI |
| Docs and claims accuracy | **Weak** | Stray markup; SECURITY/CONTRIBUTING say "no code"; several ADR claims not reflected in code |
| Packaging and supply chain | **Adequate** | Wheel clean and works standalone; no lock file or hashes, no CI, SBOM or provenance; deps currently CVE-free |
| Performance | **Good** | Stage 1 0.7 ms/KB, linear; proxy about 930 req/s; GIL stalls concurrent streams up to about 180 ms on 2 MB prompts |

---

## 2. Suitability to task

**Who it is for (PLAN §1, operator direction):** stand-alone users who point an existing client (Claude
Code, IDE agents, CLIs) at a local proxy by base URL; Kent is one integration. That makes the realistic
traffic profile:
- mostly source code, diffs, logs and tool output, repeated every turn as history;
- long contexts (hundreds of KB to MB);
- SSE streaming, and parallel agents sharing the proxy;
- sensitive data that is mostly **secrets** (keys, tokens, connection strings), internal hosts, customer
  records in fixtures and logs, and e-mail addresses in commit metadata.

**Where PPE fits well**
- Delivery by base URL with no client changes is exactly right. The pass-through proxy already handles
  real-world HTTP edge cases well.
- The insistence on byte-stable history (prompt caching, preserved thinking) shows real understanding of
  how Claude Code behaves. It's the main reason deterministic surrogates beat positional placeholders.
- Observe before mask is the right product sequence: users get a baseline of what leaves before any
  behaviour changes.
- The secret rules for well-known prefixes (AWS, GitHub, Anthropic, OpenAI, Slack, Google, Stripe, PEM,
  JWT, URL credentials) are the highest-value detectors for this audience.

**Where it does not fit yet**
- **Precision on code (F-02).** The corpus that scores 1.000 everywhere is prose and form-like text written
  alongside the detectors. Real code is a different distribution. Until precision on code is measured and
  gated, the observation plane will mostly record noise, and masking would damage answers.
- **The SG-identifier emphasis** (NRIC/FIN, IBAN, SG phones) matters for regulated SG workloads. For a
  developer audience the ranking is secrets, then internal infrastructure, then personal data in fixtures
  and logs. Generic-secret detection (entropy plus context, as gitleaks/trufflehog do) is missing, and the
  existing generic rule is the noisiest one.
- **Claude Code specifics are unverified.** These are assumed, not observed:
  - `x-claude-code-session-id` as the conversation key;
  - `count_tokens` calls carrying the same content;
  - some calls bypassing `ANTHROPIC_BASE_URL` (`sources/claude-code-gateway.md`).

  The phase 2 exit check, running a real client through the proxy, is still open.
- **Parallel agents.** With several Claude Code subagents streaming through one proxy, a single large
  prompt scan stalls other streams by up to about 180 ms (F-18).

**Bottom line:** the right product for the right audience, but detector precision on code is the gating
item for the observation plane to be useful, and therefore for the whole phase 2 value proposition.

---

## 3. Architecture critique

### What is right

- **Egress guard (ADR-0006).** One choke point on the cloud leg, made non-bypassable by host egress
  rules, is the only topology that survives LiteLLM version churn and its 2026 supply-chain history. The
  in-process callback stays advisory.
- **Loopback-only local zone (ADR-0001)** with the explicit warning that "loopback is not local"
  (`127.0.0.1:4000` is LiteLLM) shows an excellent understanding of the failure mode.
- **Deterministic surrogates with provable non-reality (ADR-0008):** G2 invalid check digits and G1
  reserved ranges. Verified for every built type (C-11), including NANP 555-01xx and Ofcom 07700 900xxx.
- **Fully sealed 2-of-2 audit with a PQ hybrid (ADR-0010).** The cryptography is correct and
  conservative. The XOR split is a nice touch that lets shares be unwrapped in different places.
- **Mechanism, not policy (ADR-0012).** Invariants, a knob catalogue with trade-offs, `ppe explain`. It
  keeps the project honest about who decides what.

### Concerns

1. **Scope versus build.** About 4k lines of design across 13 ADRs, a threat model and controls mapping
   cover a break-glass broker with TPM policy sessions, escrow, HLL sketches, lineage, an LLM arbiter,
   two span models and an observation plane with sensors. The code is about 2.8k lines. Drift has
   already started (F-20): SECURITY.md says there is no code, PLAN says "nothing built", and the knob
   catalogue says observation is "not built" while `ppe serve` observes. *Recommendation:* declare an MVP
   path (trustworthy shadow proxy → secrets block/mask on egress → signed audit). Mark everything else
   *deferred* in the ADR status lines, and keep a "built vs designed" table in the README.
2. **One process holds everything.** `ppe serve` holds plaintext, runs detection and writes the audit
   itself, so it can also rewrite or truncate it. ADR-0004 already specifies the fix: a separate `auditd`
   account that appends via a socket, `chattr +a`, and signs checkpoints. Integrity claims rest on it, so
   it should come before more observation features.
3. **Sealing is not signing (F-03).** With public-key-only writers, confidentiality is strong but
   authenticity is zero. Anyone who can write the file can produce valid-looking sealed records. The
   design needs a writer signing key (`k_sign`, ADR-0004), held by `auditd`, plus external anchoring of
   checkpoint heads. Then a compromised host can forge only *future* records, not rewrite the signed past.
4. **The size-bucket design leaks the very thing ADR-0010 forbids (F-07).** "How much" is visible:
   - `digest_key` records sit in the 256 B bucket;
   - observe records with 0-5 findings sit in 1 KiB, 9-10 in 4 KiB, and 40-100 in 16 KiB.

   Either pad every record to one size (16 KiB costs disk) or split observe records into fixed-size
   chunks with constant-count padding entries.
5. **Determinism depends on future text (F-10).** The vault probes for collisions against the *whole
   conversation text*, including provider-authored assistant text. One restore miss that leaves a
   surrogate literally in the history re-keys that value on the next turn. The turn-1 masked text
   changes, prompt caching and thinking checks break, and the provider sees two fakes for one person.
   *Fix:* probe only against real values and issued surrogates (not raw text), or keep a per-scope
   surrogate map with a TTL. That gives up some of "no mapping table" for stability; it's a knob.
6. **Restore is text substitution, not structure-aware (F-09, F-17).** Values that JSON escaping changes
   (newlines, quotes, backslashes, non-ASCII under `ensure_ascii`) are silently not restored in tool
   arguments. Generic uses of a surrogate given name are "restored" into the real name. Phase 4 needs
   restore over parsed string leaves (tool-call JSON, SSE event payloads), not over raw bytes.
7. **Normalisation decides audit truth (F-16).** Phone normalisation is digits-only, so `+65 9123 4567`
   and `9123 4567` get different digests and surrogates. "Did this number leave?" then has to try
   variants. ADR-0002 promises E.164 with region hints.
8. **Policy is not wired into the proxy (F-19).**
   - `ppe serve` takes no `--policy` and applies no detection knobs.
   - Its `--profile` is a free string that defaults to `lab`. Invariant 6 (dev token refused outside lab)
     therefore depends on an unvalidated CLI default.
   - `ppe explain` describes a configuration the proxy does not run.

   The profile should come from the validated policy file.
9. **Listener defences specified but not built (F-08).** ADR-0001 asks for a bearer token, a Host
   allowlist and Origin rejection even on loopback. In shadow mode a DNS-rebinding page can only relay
   with its own API key and pollute the audit. Once PPE fronts local models or holds credentials, the
   same gap becomes serious. Host and Origin checks are a few lines and should land now.
10. **Python and process model.** Fine for pre-alpha. The observation worker shares the GIL with the
    relay (F-18), and plaintext can't be zeroised (acknowledged in ADR-0002). Moving detection into a
    worker process (as ADR-0005 already plans for span models) fixes the stalls and narrows the memory
    exposure of the relay process.

---

## 4. Technical approach, module by module

| Module | Assessment |
|---|---|
| `core/checksums.py` | Correct. M-series confirmed against an independent implementation (M1235467X, C-04). Nit: `isdigit()` accepts superscripts that `int()` rejects, so the validator raises instead of returning False (F-21) |
| `core/shadow.py`, `normalise.py` | Offset-mapped NFKC shadow is solid and cheap. Missing: confusable folding, digit de-spacing, bounded decoding, cross-message window (ADR-0005 design; F-15). E-mail normaliser correct; phone normaliser not E.164 (F-16) |
| `detectors/` | Clean pipeline with priority-based overlap resolution, now linear. The regexes are tuned to prose: the IPv6 pattern accepts `::` and partial forms (F-02, and the partial-span leak in F-15), cards have no IIN or context check, e-mail accepts protocol identifiers (`…@openssh.com`), the `assignment` secret rule matches code expressions. No suppression or allowlist mechanism |
| `core/surrogates.py`, `vault.py` | G1/G2 constructions verified for all built types; secrets keep prefixes and end in `EXAMPLE`; collision probing works (C-12). Probing against raw conversation text causes F-10 |
| `core/engine.py` | R1 closed-world, R2 tolerance and type check, R3 round trip including model-authored identifiers all hold (C-15..C-17). R4 fails (F-09); ambiguity rule and case-insensitive domains missing (F-17) |
| `audit/envelope.py`, `keys.py` | Correct and conservative; wrap swapping across records fails (C-24); token share alone opens nothing (C-23); key files 0600 enforced (C-27) |
| `audit/log.py` | Hash chain detects in-log edits (C-28). No locking (two writers break the chain), no torn-line tolerance (`ppe audit verify` and `ppe serve` crash after a crash mid-write), no signatures (F-03, F-11) |
| `proxy/app.py` | Very good HTTP hygiene: re-framing, hop-by-hop stripping, no redirects, no cookie jar, compiled parser required, TLS verified, bomb bounded. Defects: request auto-decompression (F-04), parser-error logging and echo (F-05), no Host/Origin checks (F-08), `Server: Python/3.12 aiohttp/3.14.5` on PPE-made responses (F-19) |
| `proxy/observe.py` | Good design (sealed digests, per-conversation dedup, block cache, coverage reasons). Silent loss when a record exceeds 16 KiB, JSON nesting is too deep, or the audit is unwritable (F-06). In-memory failure and drop counters are never surfaced; `dropped_before` is lost on shutdown |
| `cli/main.py` | Expected errors (permissions, existing keys, bad listen address) end in tracebacks. `[::1]:PORT` passes the check and then fails to bind (F-19). Scan preview shows first and last characters, which is two thirds of a 3-character term (F-21) |

---

## 5. Testing method

**Strengths**
- Property-based tests (Hypothesis) for R3 and for the overlap resolver against a naive reference.
- A request-smuggling matrix and a 300-case mutation fuzz on the proxy; disconnect, stall and concurrency
  cases.
- `ppe verify` turns key claims into runnable self-checks on synthetic data.
- The corpus reports known gaps separately instead of hiding them, and the README says its numbers are a
  regression floor.
- A Trojan Source guard on source files.

**Weaknesses (measured)**
- **Mutation score 21/31 (68 %).** Ten deliberately injected security bugs went unnoticed
  (`bench/review-2026-10-16/results/mutation_before_conformance.txt`):
  - wrong M-series check letter;
  - IBAN accepting mod-97 = 0;
  - assistant history freshly re-detected (later shown to be an equivalent mutant: no R3 effect);
  - token TYPE label not checked;
  - a surrogate allowed to equal a real value;
  - both key-file permission checks removed;
  - digest not bound to type;
  - e-mail domain case not normalised;
  - finer padding buckets.
- **Circular tests.** The checksum series test validates the implementation with itself. No external
  known-answer vectors existed for M-series FINs.
- **Own-distribution evaluation.** Detection is scored only on a corpus written next to the detectors (all
  1.000 except phone precision). No negative corpus of code, logs or JSON payloads exists, which is why
  F-02 went unnoticed.
- **Weak oracles in self-checks.** The padding check pads five identical records, so it cannot detect size
  leakage (mutant M32 survived).
- **Coverage gaps.** 89 % branch coverage overall, but `cli/main.py` is at 54 %. Key creation and
  permission paths were untested.
- **One-directional checks.** The phase 2a gzip test covered responses only, and request-side
  decompression (F-04) slipped through. Proxy tests need a "both directions" checklist.
- **No CI,** no Python version matrix, `tests/adversarial/` is empty (PLAN phase 1 exit check), no fault
  injection for audit write failures, no soak or memory tests.
- **`ppe verify` against a live deployment** (ADR-0012 §5: signed, sealed report) is not built; it runs
  fixed synthetic checks.

**What this review added:** `tests/conformance/`, 68 claim-indexed tests:
- 29 pass and pin behaviour that was previously untested;
- 39 are `xfail(strict=True)` and document each failing claim with its finding id.

The suite stays green and turns red the moment a defect is fixed, so the marker can be removed. With it,
the mutation score improved; see §6.1.

---

## 6. Conformance results

Legend: **PASS** verified by test or measurement · **FAIL** claim not met (finding id) · **DESIGN** claimed in
an ADR as design, not yet built (documented, so not a defect of the code, but the claim isn't true yet).

| C | Claim (short) | Source | Result |
|---|---|---|---|
| C-01 | Stage 0 folds full-width, zero-width, bidi | README status | PASS |
| C-02 | Stage 1 linear, < 1 ms/KB | ADR-0005 amendment | PASS (0.68 / 0.70 / 0.76 ms/KB at 10 / 100 / 400 KB) |
| C-03 | 12 secret rules | RESUME | PASS |
| C-04 | NRIC/FIN incl. M-series, Luhn, IBAN correct | README | PASS (independent M vector); robustness nit F-21 |
| C-05 | Phone knob trade-off numbers (1.000/0.917; 0.850/1.000) | knobs.py | PASS (reproduced exactly) |
| C-06 | Corpus deterministic, sha256 3a4f7aa9… | RESUME, generator | PASS |
| C-07 | Detectors usable on coding-agent traffic | PLAN §1 audience | **FAIL F-02** (about 133 findings per MB of code) |
| C-08 | Cards = Luhn + IIN ranges | ADR-0005 | **FAIL F-02** (10.3 % of random 16-digit ids, IMEIs) |
| C-09 | No identifier leaves in clear, even partly | threat model §1 | **FAIL F-15** (`::ffff:192.0.2.10` keeps `.0.2.10`) |
| C-10 | Confusables, de-spacing, bounded decoding | ADR-0005 Stage 0 | DESIGN (F-15): homoglyph, spaced, %-encoded, HTML-entity, dotted card all missed |
| C-11 | G1/G2 surrogate guarantees, all built types | ADR-0008 | PASS (incl. NANP/UK phones, secrets) |
| C-12 | Surrogate never equals a real value | ADR-0008, vault | PASS (forced collision probed away) |
| C-13 | Stable within, unlinkable across conversations | ADR-0002 | PASS |
| C-14 | Byte-stable history even after a restore miss | ADR-0002/0008 | **FAIL F-10** |
| C-15 | R1 closed-world restore (invariant 4) | ADR-0002 | PASS |
| C-16 | R2 bounded tolerance, TYPE must match | ADR-0002 | PASS |
| C-17 | R3 round trip incl. model-authored identifiers | ADR-0002 | PASS |
| C-18 | R4 restore into JSON tool arguments | README, ADR-0002, PLAN ("R1-R4 built") | **FAIL F-09** (silent non-restore) |
| C-19 | E-mail domain case-insensitive restore | ADR-0008 | **FAIL F-17** |
| C-20 | Name components restored only in name context | ADR-0008 | **FAIL F-17** |
| C-21 | Phone normalised to E.164 | ADR-0002 | **FAIL F-16** |
| C-22 | E-mail domain lower-cased in normaliser | ADR-0002 | PASS |
| C-23 | Either share alone reveals nothing (2-of-2) | ADR-0010 | PASS |
| C-24 | Header bound; wraps can't move between records | ADR-0010 | PASS |
| C-25 | Record sizes don't fingerprint event type or volume | ADR-0010 | **FAIL F-07** |
| C-26 | Dev token refused outside lab, marked `dev-1234`; CLI rails | invariant 6, ADR-0010 | PASS (but `ppe serve` defaults to lab, F-19) |
| C-27 | Private key files 0600 enforced | ADR-0003/0010 | PASS |
| C-28 | Chain detects modify, reorder, delete, insert | ADR-0004, invariant 7 | PASS |
| C-29 | Tamper-evident against truncation and rewrite | README | **FAIL F-03** |
| C-30 | Chain stays valid with two writers | invariant 7 | **FAIL F-11** |
| C-31 | Torn final line reported, not fatal | robustness | **FAIL F-11** |
| C-32 | Observation digest bound to type | ADR-0009 | PASS |
| C-33 | Opening the audit is itself audited | ADR-0010 | DESIGN (not built) |
| C-34 | Proxy forwards traffic unchanged (incl. compressed requests) | README, app docstring | **FAIL F-04** |
| C-35 | TLS to upstream verified | threat model §5 | PASS (self-signed refused, 502) |
| C-36 | No protected value in logs or errors | invariant 1 | **FAIL F-05** |
| C-37 | Every request yields a record or a counted gap | ADR-0007, app docstring | **FAIL F-06** |
| C-38 | Host allowlist and Origin rejection | ADR-0001, threat model T4 | **FAIL F-08** |
| C-39 | Investigator with both parts can test a value or session | observe.py, ADR-0009 | PASS |
| C-40 | No `x-ppe-*` headers; opaque error refs | ADR-0010 | PASS |
| C-41 | A slow observer never delays the request | app docstring | PASS for the request itself; concurrent streams stall (F-18) |
| C-42 | `[::1]:PORT` listen form usable | ADR-0001 | **FAIL F-19** |
| C-43 | Decompression bomb bounded | threat model §5 D | PASS (100-200 MiB bomb gives 413, nothing forwarded) |
| C-44 | Published docs free of stray markup | quality | **FAIL F-01** |
| C-45 | `ppe serve` runs the configuration `ppe explain` describes | ADR-0012 §5 | **FAIL F-19** |
| C-46 | No generated checksum-valid identifiers committed | corpus/generator.py | **FAIL F-14** |
| C-47 | SECURITY/CONTRIBUTING describe the current state | SECURITY.md | **FAIL F-20** |
| C-48 | README ADR index current | README | **FAIL F-20** |
| C-49 | Every policy setting has a knob, trade-off and test | knobs.py, ADR-0012 | **FAIL F-20** (`detection.dictionary`) |
| C-50 | Docs free of invisible/bidi characters | CONTRIBUTING | PASS |
| C-51 | Version consistent and pre-alpha marked | release | PASS |
| — | Wheel works outside the repo; resources packaged | packaging | PASS |
| — | Dependencies free of known CVEs | supply chain | PASS today (pip-audit, 20 runtime / 36 dev packages) |
| — | Bench and corpus numbers reproduce | bench | PASS |

Tally: of 51 claim ids, **26 PASS, 23 FAIL, 2 DESIGN**, plus three unnumbered checks (all PASS).

### 6.1 Mutation score after the conformance suite

**Mutation re-run with the suite: 30/32 killed** (`results/mutation_after_conformance.txt`; repo-level claims deselected because the mutation copy is not a git checkout). All eight genuine earlier survivors are now caught. The two survivors are explained:
- **M08 is an equivalent mutant.** Assistant turns go through `inverse_map`, and fresh findings only feed the collision-avoidance set, so R3 cannot change. C-17 confirms R3 with model-authored identifiers.
- **M32 is masked by the known defect F-07.** C-25 is an expected failure, so finer buckets cannot fail it further. It will catch M32 once F-07 is fixed and the marker removed.

---

## 7. Findings register

Severity: **High** undermines a core claim or the product's purpose, or is a public-facing defect ·
**Medium** a stated invariant, claim or ADR requirement is not met, with a concrete trigger · **Low**
robustness, UX or docs drift · Effort: S (hours), M (days), L (a week or more).

### F-01 · High · Stray tool-call markup in 23 published docs; README embeds a git script · S
- **What:** README.md and 22 other tracked docs (ADR-0001..0012, threat model, controls mapping, research,
  six source notes) end with leftover closing `content` / `invoke` tag lines from an earlier authoring session.
  The README also contains a complete embedded tool call: a Python link checker, a `git commit`, and
  `git branch -f main HEAD`. Present since `2652af6` (2 Oct), live on GitHub, and in the wheel's long
  description.
- **Impact:** credibility on first read. Worse, an AI agent reading the repo can take the block as an
  instruction to run (this review hit it). PyPI would publish it too.
- **Fix:** delete the trailing markup from all 23 files and add C-44 to CI. Delete the two exact lines
  only, not "from the first stray line to the end": `docs/controls-mapping.md` continues with the MAS
  section after them. The README's embedded block runs from the stray lines to the end of the file.
- **Status (2026-10-16): fixed.** Markup removed from all 23 files; C-44 passes.

### F-02 · High · Stage 1 precision on source code · M
- **What:** 4.2 MB of third-party Python (335 files) gave 566 findings, about 133 per MB, essentially none
  of them personal data:

  | Type | Findings | Per MB | Cause |
  |---|---|---|---|
  | IPv6 | 359 | 84.5 | `::`, `e::` |
  | IPv4 | 89 | 20.9 | mostly `127.0.0.1` / `0.0.0.0` |
  | SECRET | 88 | 20.7 | `Final[str]`, `re.compile(`, `token_match.group(` via the `assignment` rule |
  | PHONE | 20 | 4.7 | |
  | EMAIL | 10 | 2.4 | `sk-ssh-ed25519@openssh.com` |

  On snippets, Rust `use std::io`, C++ `std::string`, Ruby `Foo::Bar`, CSS `a::before` and Python
  classifiers all yield IPv6 findings. `password = form.cleaned_data[` and `API_KEY = os.environ[` are
  "secrets". An IMEI is a "card". 10.3 % of random 16-digit ids are cards.
- **Impact:** the observation plane and any future exposure ledger would be dominated by noise for the
  primary audience. With masking on, code sent to the model would be corrupted.
- **Fix:**
  - IPv6: require at least 2 hex groups with at least one non-empty group on each side of `::`, or a full
    8-group form, plus word-boundary and context rules. Treat loopback, unspecified and private addresses
    as a separate class that the policy can ignore.
  - Secrets: in the `assignment` rule, require a literal value (quoted, or high-entropy without
    `(`, `[` or `.` attribute access); add entropy scoring and import a vetted rule set (gitleaks,
    licence permitting).
  - Cards: add IIN ranges plus context words; never treat 15-digit IMEI-shaped numbers near "IMEI" as
    cards.
  - E-mail: require a TLD from a list and drop protocol identifiers.
  - Add an inline and path allowlist mechanism.
  - Build a **negative corpus** (code, logs, JSON API payloads, synthetic Claude Code transcripts) and gate
    CI on findings per MB.
- **Evidence:** `results/code_fp.txt`, C-07, C-08.

### F-03 · High · Audit is confidential but not tamper-evident or authentic · M-L
- **What:** writers hold only public keys and nothing is signed or anchored. Tail truncation passes
  `verify_chain`. A log rebuilt from scratch with the public keys passes verification and opens with both
  parts as genuine ("fabricated history").
- **Impact:** the README's "tamper-evident, attacker-proof evidence" and the security objective's "a log
  whose integrity can be checked" are not met against anyone with write access to the file, which on a
  stand-alone install is the user and any same-uid malware.
- **Fix:** ADR-0004 as written:
  - a separate `ppe-auditd` account that appends via a socket and holds `k_sign`;
  - Ed25519-signed C2SP checkpoints every N records or T seconds;
  - `chattr +a`;
  - optional off-host anchoring or witnessing;
  - `ppe audit verify` that checks signatures and reports an unsigned tail.

  Until then, reword the README to "hash-chained; signed checkpoints planned".
- **Evidence:** `results/probe_core.txt` P12/P13, C-29.

### F-04 · Medium · Proxy decompresses gzip request bodies and forwards them under a gzip label · S
- **What:** aiohttp's server auto-decompresses request bodies. `ppe serve` forwards the decoded bytes (75 B
  JSON instead of 86 B gzip) while keeping `Content-Encoding: gzip`, so the upstream rejects or misreads
  the request. Other encodings aiohttp decodes are presumably affected the same way.
- **Impact:** violates "forwards traffic unchanged". Breaks any client that compresses requests.
- **Fix:** `web.Application(handler_args={"auto_decompress": False})`. For observation, decode a bounded
  copy (respecting `client_max_size`). Add request-direction tests for gzip, deflate and br.
- **Evidence:** `results/probe_proxy.txt` P1, C-34.
- **Status (2026-10-16): fixed.** The relay forwards the client's bytes with `Content-Encoding` intact; the
  observer decodes a bounded copy (gzip, x-gzip, deflate incl. raw; br/zstd are a counted
  `unsupported_encoding` gap) capped at `max_body`. C-34 passes. C-43 is restated: its original form (413
  for a small gzip body that decodes past 64 MiB) required relay-side decoding and contradicted C-34; it
  now checks that the bomb is forwarded as sent, observation stops at the cap with a `decoded_too_large`
  gap, and a raw body over the cap still gets 413.

### F-05 · Medium · Invariant 1: request bytes (incl. identifiers) reach logs and error bodies · S
- **What:** on malformed requests aiohttp's parser error path logs the offending bytes
  (`b'X-Note: S1234567D\x00'`). With no logging configured, which is how `ppe serve` runs, Python's
  last-resort handler prints them to stderr, and from there to journald. The default 400 body echoes the
  same bytes.
- **Impact:** a client bug or deliberate input can put a protected value into persistent system logs,
  contradicting invariant 1 ("never ... logs, errors").
- **Fix:**
  - install a logging filter or handler that strips `exc_info` and arguments from `aiohttp.server` and
    `aiohttp.access`;
  - customise parser error responses (custom `RequestHandler.handle_error` or a low-level server
    subclass) to a generic body with an opaque ref;
  - turn invariant 1 into a fuzz assertion (no NRIC from a planted set in any log line or response).
- **Evidence:** `results/probe_logs.txt`, C-36.
- **Status (2026-10-16): fixed.** `ProxyRunner` installs a protocol handler whose errors (parser errors
  and handler crashes) carry a fixed body with an opaque ref and are logged by exception type only; the
  access log is always off (the request line carries the path and query); `ppe serve` also filters
  aiohttp/asyncio log records down to template + exception type. C-36 passes; a new fuzz test plants an
  NRIC in the path, a header and the body of 200 mutated requests and checks every response and log line.
  The fuzz caught one more path on the way: the access log, which the test server enables by default.

### F-06 · Medium · Observation can be evaded silently · S
- **What:** the request still flows, but **no record and no counted gap** is written when:
  - a sealed record would exceed 16 KiB (e.g. a 20 KB `model` string): `ValueError`;
  - JSON nesting exceeds the recursion limit: `RecursionError`;
  - the audit file isn't writable.

  The in-memory `failures` and `dropped` counters are never surfaced, and `dropped_before` is lost at
  shutdown.
- **Impact:** coverage claims (ADR-0007: drops are "coverage gaps") don't hold. A client (T8) can opt out
  of observation at will.
- **Fix:**
  - bound or hash every variable-length field (`model`, `path`);
  - catch everything in `observe()` and append a fixed-size `observe_failed` gap record with a reason
    code;
  - parse with a depth limit;
  - expose health counters;
  - write `dropped`/`failed` totals in a shutdown record.
- **Evidence:** `results/probe_proxy.txt` P5/P6, C-37.
- **Status (2026-10-16): fixed.** Any failure of the scan becomes a record with `scanned: false` and a
  reason code (`too_deep`, `observer_error:<Type>`); `model` and `path` are bounded, scanned like the body
  (identifiers there now count as exposure, query string included) and withheld when long or holding a
  finding; requests that could not be recorded at all are counted and carried (once) into the next record;
  an `observe_stop` record with totals is written at shutdown. C-37 passes.

### F-07 · Medium · Padding buckets leak event type and identifier volume · S-M
- **What:** the padded ciphertext (base64) is 363 B for `digest_key`, 1,387 B for observe with 0-5
  findings, 5,483 B for 9-10 findings and 21,867 B for 40-100 findings.
- **Impact:** contradicts ADR-0010 ("sizes don't fingerprint event types"; nobody may learn "how much").
  An attacker with the file learns restarts and per-request volume. The self-check can't see it because
  its records are identical.
- **Fix:** one constant record size for all event types (e.g. 16 KiB, or 4 KiB with chunking at a fixed
  number of findings per record and dummy entries), at the cost of disk. Test with heterogeneous records
  (C-25).

### F-08 · Medium · Listener lacks the defences ADR-0001 specifies · S (Host/Origin), M (auth)
- **What:** any `Host` and any `Origin` are accepted and forwarded. There's no bearer token and no
  UNIX-socket option.
- **Impact:** a DNS-rebinding web page can drive the proxy. Today that means relay with its own key plus
  audit pollution. It becomes serious once PPE fronts local models (observe leg) or holds credentials.
- **Fix:** allow `Host` only for `localhost`, `127.0.0.1`, `[::1]` (+ port); reject any request with an
  `Origin` header not on an allowlist; then add a bearer token from a 0600 file and a UNIX socket mode.
- **Evidence:** C-38.
- **Status (2026-10-16): Host/Origin fixed.** `Host` must be `localhost` or a loopback literal (optional
  port), else 421; any `Origin` not in `allowed_origins` (empty by default) gets 403; both before the body
  is read, so nothing reaches the upstream or the audit. C-38 passes. Bearer token and UNIX socket: open.

### F-09 · Medium · Restore isn't context-aware (R4); misses are silent · M
- **What:** a PEM-key surrogate inside JSON tool arguments (`json.dumps` escapes the newlines) is not
  restored at all (`restored=0`) and isn't counted as a miss. The same applies to any value that JSON
  escaping changes.
- **Impact:** tools would receive fake values. The README's "restored ... including tool-call arguments"
  and PLAN's "restore R1-R4 built" overstate.
- **Fix:** restore over parsed structure (JSON string leaves in tool input, SSE delta payloads), apply
  JSON escaping on insertion, and count any issued surrogate surface left in the output as
  `restore_incomplete`.
- **Evidence:** C-18.

### F-10 · Medium · Surrogate re-keys after a restore miss (byte stability) · S-M
- **What:** collision probing checks `s.canonical in conversation_text`. If an earlier surrogate appears
  literally in the history (an unrestored reformat, or a user quoting it), the same real value gets a new
  surrogate on the next turn (`S9817843R` → `S2523178H`), and the turn-1 masked text changes.
- **Fix:** probe only against real values and issued surrogates of the scope, not raw text; or keep a
  per-scope issued map (TTL) as an opt-in knob.
- **Evidence:** C-14.

### F-11 · Medium · Audit log: no locking, no crash tolerance · S
- **What:**
  - Two writers (e.g. `ppe serve` plus `ppe audit append`, or two `serve` instances) each keep their own
    `seq`/`prev`, and the chain breaks ("sequence gap").
  - A torn final line after a crash makes `ppe audit verify` and `ppe serve` start-up raise
    `JSONDecodeError`.
- **Fix:** take `fcntl.flock` around read-tail-and-append; detect and report a torn last line
  (`verify` returns BROKEN with a "torn tail" reason, and the writer truncates it after recording a
  `recovered` event); in the end, a single `auditd` writer.
- **Evidence:** C-30, C-31.
- **Status (2026-10-16): fixed** (`flock` per append, chain state read from the file's tail, torn
  tail cut and replaced by a sealed `recovered` record; `verify` reports "torn tail"). C-30/C-31 pass. The
  single `auditd` writer stays with F-03.

### F-12 · Medium · Testing method gaps · M
- **What:** mutation score 21/31 (§5); circular checksum tests; detection scored only on the
  author-written corpus; weak padding oracle; CLI 54 % covered; empty `tests/adversarial/`; no fault
  injection; no CI.
- **Fix:**
  - keep `tests/conformance/` and remove each xfail as its finding is fixed;
  - add external known-answer vectors (with citations) for every checksum;
  - add the negative code corpus (F-02);
  - add CLI tests;
  - make mutation testing a periodic job (mutmut or the script in `bench/review-2026-10-16/scripts/`).

### F-13 · Medium · No CI, lock file, CHANGELOG, SBOM or provenance · S-M
- **What:** all promised in PLAN §2. Dependencies are open ranges (`>=`) without hashes, so threat T7
  (supply chain) mitigations aren't in place. pip-audit is clean today.
- **Fix:** a GitHub Actions workflow (ruff, mypy, pytest incl. conformance, hygiene, pip-audit, build, a
  Python 3.12/3.13 matrix); `uv lock` with hashes; CHANGELOG; CycloneDX SBOM; trusted publishing with
  attestations when PyPI comes.

### F-14 · Medium (policy) · Generated, checksum-valid identifiers are committed and shipped in the sdist · S
- **What:** `bench/results/2026-10-03/raw_10kb_doc1700.txt` and `raw_1kb.json` contain corpus output:
  - 10 checksum-valid NRIC/FINs;
  - 3 Luhn-valid cards with real-network prefixes;
  - 1 mod-97-valid IBAN;
  - 10 SG-shaped phone numbers;
  - 22 key-shaped strings.

  The generator's own docstring says such values "can coincide with a real one by chance, so the corpus
  is generated at test time and not committed". Random valid S/T-series NRICs in particular can belong to
  real people. CONTRIBUTING also says "deliberately invalid check digits", yet the README and tests use the
  checksum-valid published sample `S1234567D`.
- **Fix:**
  - replace the raw files with summaries and regenerate them at test time;
  - decide whether to purge them from public history (a rewrite of `main`; operator decision);
  - exclude `bench/results/` from the sdist;
  - refine the rule to "published sample values (`S1234567D`, `4111…`) or values generated at test time".
- **Evidence:** `results/selfscan.txt`, C-46.

### F-15 · Medium · Detection gaps: partial-span leak, plus unbuilt Stage 0 normalisations · S / M
- **What:**
  - `::ffff:192.0.2.10` is detected as `::ffff:192`, so masking leaves `.0.2.10` (3 octets) in clear.
  - Cards with dot or mixed separators are missed.
  - Designed but not built (ADR-0005): homoglyph NRIC (Cyrillic S), spaced digits (`S 1 2 3 …`),
    percent-encoded and HTML-entity e-mail, base64, identifiers split across messages.
- **Fix:** extend the IPv6 pattern to embedded-IPv4 forms (and prefer the longest valid span); then build
  Stage 0 per ADR-0005 (UTS #39 skeleton, digit de-spacing, bounded decoding).
- **Evidence:** C-09, C-10.

### F-16 · Low · Phone normalisation is digits-only, not E.164 · S-M
- **What:** `+65 9123 4567` normalises to `+6591234567`, and `9123 4567` to `91234567`.
- **Impact:** different surrogates and audit digests for one number.
- **Fix:** E.164 with a policy region default (libphonenumber, or a small SG/NANP/UK normaliser). Version
  bump `NORM_VERSION`.

### F-17 · Low · ADR-0008 restore rules not implemented · S
- **What:** e-mail domains are matched case-sensitively (`…@EXAMPLE.ORG` is not restored), and the name
  ambiguity rule is missing ("For example, *Daniel* is a common name" becomes "… *Jane* …").
- **Fix:** case-insensitive domain matching; restore components only next to another issued component,
  a title or a capitalised context, and count the rest as `restore_ambiguous`.

### F-18 · Low · Observation shares the GIL with the relay · M
- **What:** scanning a 2 MB prompt stalls concurrent streams by up to 156-183 ms (p99 58-73 ms) against
  about 7 ms idle. The request itself isn't delayed (C-41).
- **Fix:** run detection in a worker process (ProcessPoolExecutor) or scan in bounded windows.

### F-19 · Low · Configuration and CLI rough edges · S
- **What:**
  - `ppe serve` has no `--policy`, so detection knobs aren't applied (C-45).
  - `--profile` is an unvalidated string defaulting to `lab`, which keeps the dev-token rail open.
  - `--listen [::1]:PORT` passes validation, then fails (`socket.gaierror`) (C-42).
  - Expected errors end in tracebacks.
  - An `http://localhost` upstream is classed as loopback through the system resolver (ADR-0001 says
    never use the resolver).
  - PPE-made responses carry `Server: Python/3.12 aiohttp/3.14.5`.
- **Fix:** `serve --policy` (required outside lab), profile taken from the policy; strip brackets; friendly
  error messages; map `localhost` to `127.0.0.1` internally; drop or override the Server header.

### F-20 · Low · Docs drift · S
- **What:**
  - SECURITY.md and CONTRIBUTING.md say "design phase, no executable code".
  - PLAN says "Status: planning … Nothing built", and its layout (ASGI, `adapters/proxy`,
    `requirements/`, CHANGELOG, TODO) differs from the repo.
  - The README ADR index stops at 0012.
  - The knob catalogue says observation is "designed, not built"; `detection.dictionary` has no knob.
  - ADR-0002 says Crockford base32 (the code uses RFC 4648).
  - ADR-0006 uses a `/anthropic` path prefix (the code doesn't).
  - ADR-0001 and ADR-0010 name `standard`/`hardened` profiles that the schema doesn't have.
  - The threat model says "nothing is built".
- **Fix:** one docs pass, plus a "built vs designed" table in the README; C-47/48/49 then turn green.

### F-21 · Low · Robustness and minor-leak nits · S
- **What:**
  - Checksum validators raise on non-ASCII digits.
  - `ppe audit keygen` would overwrite `token.salt` if `machine.key` were missing while the salt existed.
    That makes an earlier passphrase-derived token part unrecoverable (code inspection; not exercised,
    because the passphrase path is interactive).
  - `ppe audit open` doesn't write its own audit record (ADR-0010).
  - The scan preview reveals first and last characters (two thirds of a 3-character term).
- **Fix:** `isascii()` checks; refuse to overwrite an existing salt; self-audit on open; preview as type
  and length only for values of 6 characters or fewer.

---

## 8. Enhancements and roadmap

### Now (before anyone else runs v0.1.0.dev1)
1. F-01: strip the stray markup (and republish the README); add C-44 to CI.
2. F-04, F-05, F-06, F-08 (Host/Origin): small, contained proxy fixes with tests already written.
3. F-11: `flock` plus torn-tail handling.
4. F-03 wording: README "hash-chained; signed checkpoints planned" until they exist.
5. F-14: replace the raw bench files; decide on history.
6. F-20: docs pass (SECURITY/CONTRIBUTING status, PLAN status, README index, built-vs-designed table).

### Next (to finish phase 2 with a useful observation plane)
7. **F-02 precision on code, with a negative corpus and a CI gate.** This is the gating item for the
   exposure ledger.
8. F-19: `serve --policy`, profile from policy, dev-token rail closed by default.
9. F-07: constant-size records; F-03: `auditd` plus signed checkpoints (ADR-0004).
10. CI, lock file with hashes, CHANGELOG, SBOM (F-13).
11. Reply-flow observation (already planned), and the operator's Claude Code exit check.

### Before masking (phase 4)
12. F-09 structure-aware restore (tool JSON, SSE deltas) with an R5 holdback design and tests.
13. F-10 stable surrogates; F-16 E.164; F-17 restore rules; F-15 Stage 0 normalisations.
14. F-18 worker-process detection; plan the span models as separate processes from the start.

### Product ideas
- `ppe report` (minimal exposure summary from the sealed log, decrypter-side); `ppe doctor` (base URL,
  egress rules, Claude Code `allowedProviders`).
- A first-class **secrets-only mode** for developers (block or mask provider keys, PEM, URL credentials)
  as the first enforcement feature. It's the highest-value, lowest-false-positive slice for the target
  audience.
- Suppression mechanisms (inline `ppe:ignore`, path globs, value allowlists) with sealed records of their
  use.
- Treat loopback, private and documentation IP ranges as a separate class that the policy can ignore.
- A Claude Code setup guide covering the calls that bypass `ANTHROPIC_BASE_URL`.

### Scope management
- Mark ADR statuses (accepted / deferred / superseded). Move break-glass broker, escrow, HLL and lineage
  to a "later" list so the core stays shippable.

---

## 9. What is genuinely strong (keep it)

- **Design discipline.** Invariants, trade-off statements and reference profiles, and an explicit "not
  anonymisation" stance. Rare and valuable.
- **Correct crypto, used conservatively.** Hybrid PQ HPKE, per-record DEKs, XOR 2-of-2, AAD binding,
  Argon2id stand-in. Verified by wrap-swap, single-share and tamper tests.
- **Honest reporting.** Known gaps are reported separately; the bench is labelled a regression floor;
  `ppe explain` flags unbuilt knobs.
- **HTTP hygiene of the proxy:**
  - 27/27 ambiguous framings rejected with nothing forwarded;
  - clean re-framing, no redirects, no cookie jar, compiled parser required;
  - TLS verified, bombs bounded;
  - +0.4 ms p50, about 930 req/s with a sealed, fsynced record per request.
- **Determinism and R3.** Byte-stable history holds through restore and resend, including model-authored
  identifiers (C-17), in the normal case.
- **Packaging.** A clean wheel that runs outside the repo, with a friendly message when the `serve` extra
  is missing. Dependencies are CVE-free today.
- **Performance of Stage 1** after the scaling fix: 0.7 ms/KB, linear to 400 KB.

---

## 10. Method, reproducibility, limits

**What was run**
1. Read all source (2.8k lines), tests (1.2k), README, PLAN, threat model, ADR-0001/0002/0005/0008/0010/
   0012 in full and the claims sections of ADR-0004/0006/0007.
2. Probes: `bench/review-2026-10-16/scripts/`, each with raw output in `results/`:

   | Script | What it probes |
   |---|---|
   | `probe_core.py` | engine, surrogates, audit, detection |
   | `probe_proxy.py` | proxy |
   | `probe_logs.py` | invariant 1 |
   | `code_fp.py` | code false positives |
   | `selfscan.py` | dogfood scan of the repo |
   | `perf_proxy.py` | latency, throughput, GIL |
   | `mutate.py` | 32 targeted mutants |

3. Coverage, pip-audit, a wheel build and clean install, and the bench and corpus reproduction:
   `results/other_checks.txt`.
4. Conformance suite: `tests/conformance/` (68 tests).
   - Run with `pytest tests/conformance -rxX`.
   - `--runxfail` shows each failing claim's actual assertion.
   - Each xfail is `strict`, so a fix flips it to an XPASS failure, telling you to remove the marker.

**Mutation re-run with the suite: 30/32 killed** (`results/mutation_after_conformance.txt`; repo-level claims deselected because the mutation copy is not a git checkout). All eight genuine earlier survivors are now caught. The two survivors are explained:
- **M08 is an equivalent mutant.** Assistant turns go through `inverse_map`, and fresh findings only feed the collision-avoidance set, so R3 cannot change. C-17 confirms R3 with model-authored identifiers.
- **M32 is masked by the known defect F-07.** C-25 is an expected failure, so finer buckets cannot fail it further. It will catch M32 once F-07 is fixed and the marker removed.

**Limits**
- No real provider or Claude Code traffic. Upstreams were local fakes.
- No span models or GPU.
- Code false-positive rates measured on Python (third-party packages) plus synthetic snippets for other
  languages.
- The mutation set is targeted (32 security-relevant mutants), not exhaustive.
- Performance is from this host (Ryzen 7 3700X, 3 pinned cores).
- No legal or regulatory review.
- The M-series check letter is confirmed against one independent implementation's published example, not
  an ICA specification.

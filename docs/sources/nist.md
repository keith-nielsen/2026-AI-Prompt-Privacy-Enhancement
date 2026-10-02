# NIST / US federal baseline (operator's choice, 2026-10-02)

Status per publication checked by web search on 2026-10-02. Control text for SP 800-53r5 is cited
from the catalogue as commonly reproduced (UpGuard, STIG Viewer, myctrl.tools); **primary catalogue
not re-read line by line** — verify wording before quoting in `controls-mapping.md` final.

| Publication | Status (2026-10-02) | Used for |
|---|---|---|
| SP 800-53 Rev. 5.1 (+ 800-53B baselines) | final | control mapping (AC-4 family, AU, SC, SI, PT, SR) |
| FIPS 198-1 HMAC → **SP 800-224** (HMAC spec + truncation) | 800-224 initial public draft 28 Jun 2024; final to be issued with FIPS 198-1 withdrawal | token and digest construction |
| SP 800-107 Rev. 1 (applications of hash functions; truncation) | final (2012) | truncated HMAC rationale |
| SP 800-38G (FF1/FF3) → **SP 800-38G Rev. 1** | Rev. 1 **second public draft 3 Feb 2025**, still draft; **FF3/FF3-1 removed** (Beyne, CRYPTO 2021), FF1 only, minimum domain raised (10^6 in 1st draft) | why format-preserving encryption is not the default |
| SP 800-57 Pt 1 Rev. 5 (key management, cryptoperiods) | final | key lifetimes, rotation |
| SP 800-108 Rev. 1 (KBKDF) / SP 800-56C Rev. 2 (two-step KDF; HKDF-compatible) | final | deriving sub-keys |
| SP 800-90A Rev. 1 (DRBG) | final | key generation via OS CSPRNG (`getrandom`) |
| FIPS 140-3 | final | optional: OpenSSL 3 FIPS provider for HMAC/SHA-2 |
| SP 800-92 Rev. 1 (Cybersecurity Log Management Planning Guide) | **initial public draft 11 Oct 2023**, not final | log planning plays |
| SP 800-122 (PII confidentiality) | final 2010; revision under development | PII confidentiality impact levels → data classes |
| SP 800-188 (de-identifying government datasets) | final 2023 | pseudonymisation vocabulary, re-identification risk |
| AI 100-1 AI RMF 1.0 + **AI 600-1 GenAI Profile** (Jul 2024) | final | GAI risks "Data Privacy", "Information Security"; MEASURE 2.10 (privacy risk examined and documented) |
| Privacy Framework 1.1 | draft 14 Apr 2025 (final expected Q4 2025; final not confirmed in this search) | AI privacy section; CSF 2.0 alignment |

## SP 800-53r5 controls most directly on point

The package is, structurally, a **content filter on an information flow between security domains**
(local host → cloud provider). NIST places such filters under AC-4; enhancements 3–32 "primarily
address cross-domain solution needs … such as high-assurance guards".

| Control | Short text (paraphrased) | PPE feature |
|---|---|---|
| AC-4 | enforce approved authorisations for information flow within and between systems | zone policy: what may leave to which zone |
| AC-4(8) | security and privacy policy filters as the basis for flow decisions; **block, strip, modify, or quarantine after filter failure** | detectors + actions; `on_error` never passes in non-lab profiles |
| AC-4(12) | data type identifiers | entity classes / types |
| AC-4(14) | policy filter constraints | schema-validated policy |
| AC-4(15) | detection of unsanctioned information | secrets / special-class detection → block / keep local |
| AC-4(23) | modify non-releasable information before transfer | swap (pseudonymise) |
| AC-4(26) | audit filtering actions | one audit record per action |
| **AC-4(27)** | **redundant / independent filtering mechanisms** | ensemble of independent detectors (ADR-0005) |
| AC-4(28) | linear filter pipelines | ordered, non-bypassable pipeline |
| AC-4(29)/(30) | filter orchestration engine; filters in multiple processes | detector isolation (separate processes for NER / LLM) |
| AC-4(31) | failed content transfer prevention | fail closed |
| AC-4(21) | physical or logical separation of flows | local vs cloud deployments; loopback verification |
| SC-7, SC-7(10) | boundary protection; prevent exfiltration | egress allowlist so only PPE reaches providers |
| SC-8 | transmission confidentiality | TLS to providers; unix socket locally |
| SC-12 / SC-13 | key establishment and management; cryptographic protection | key hierarchy, HMAC-SHA-256 |
| SC-28(1) | protection of information at rest (crypto) | audit store, escrow (option C) |
| SC-39 | process isolation | privilege-separated audit writer |
| SI-4 | system monitoring | metrics, alerts |
| SI-10 | information input validation | request schema validation |
| SI-12, SI-12(1), SI-12(3) | information management and retention; limit PII elements; disposal | retention job, crypto-shredding |
| SI-15 | information output filtering | reply-side scan (log / restore) |
| **SI-19, SI-19(4)** | de-identification; **removal, masking, encryption, hashing or replacement of direct identifiers** | the core transform |
| AU-2/3/12 | event logging, content of records, generation | audit schema |
| AU-6 | review, analysis, reporting | `ppe report` |
| AU-9, AU-9(3), AU-9(4) | protect audit info; cryptographic protection; access by a subset of privileged users | hash chain + signed checkpoints; operator-only group |
| AU-10 | non-repudiation | signed checkpoints, caller identity in records |
| AU-11 | audit record retention | retention policy with rationale |
| PT-2 / PT-3 | authority / purpose for processing PII | policy template (deployer) |
| SR-3 / SR-4 / SR-11 | supply chain controls; provenance; component authenticity | hash-locked deps, pinned weights, SBOM (LiteLLM compromise, Mar 2026) |
| SA-8 | security and privacy engineering principles | reference-monitor design (README) |

## Implications

1. Frame PPE as an AC-4 guard: fail closed (AC-4(8), (31)), redundant independent filters (AC-4(27)),
   audited filter actions (AC-4(26)) — these give the ensemble and fail-closed defaults a federal
   basis, not only a best-practice one.
2. Token = truncated HMAC-SHA-256 (FIPS 198-1 / SP 800-224 draft), keys from the OS CSPRNG,
   sub-keys by an SP 800-108/56C KDF, cryptoperiods per SP 800-57. FPE (FF1) stays an option only;
   800-38G Rev. 1 is still a draft.
3. The deployer's NIST AI 600-1 MEASURE 2.10 evidence is the package's bench report and audit.
</content>
</invoke>

# Controls mapping (draft 0, 2026-10-02)

Maps each requirement to the PPE feature that serves it and the evidence the deployer can show.
"Evidence" items do not exist yet (nothing is built). NIST control wording to be re-checked against
the primary SP 800-53r5 catalogue before v0.1.0 (see [sources/nist.md](sources/nist.md)).

| Requirement | Source | PPE feature | Evidence |
|---|---|---|---|
| Information flow enforcement between domains | NIST AC-4 | zone policy; egress guard (ADR-0001, 0006) | policy file + `ppe doctor` report |
| Policy filters; block/strip/modify/quarantine after filter failure | NIST AC-4(8), AC-4(31) | detectors → actions; fail closed `on_error` (ADR-0005) | config; fault-injection tests |
| Redundant, independent filtering mechanisms | NIST AC-4(27), (30) | rules + two span models in separate processes + arbiter (ADR-0005) | bench detector-agreement matrix |
| Detect unsanctioned information | NIST AC-4(15) | secrets/special classes → block/keep local | bench per class |
| Modify non-releasable information | NIST AC-4(23); SI-19(4) | swap with keyed tokens (ADR-0002) | unit/property tests (R1–R6) |
| Audit filtering actions | NIST AC-4(26); AU-2, AU-3, AU-12 | audit record per action (ADR-0004) | schema + sample records |
| Protect audit information; crypto protection; restricted access | NIST AU-9, AU-9(3), AU-9(4) | auditd, hash chain, signed checkpoints, operator group; value-derived fields sealed to an offline key (ADR-0009) | `ppe audit verify`; theft acceptance test |
| Minimise PII in records; dual authorisation for sensitive actions | NIST SI-12(1), AC-3(2) | fully sealed records, 2-of-2 decryption (machine + token) (ADR-0010); two-person investigation | decrypter's own sealed records |
| Separation of duties; dual authorisation; temporary, auto-expiring access | NIST AC-5, AC-3(2), AU-9(5), AC-2(2), AC-2(3), IA-2(1) | break-glass broker: 2 approvers ≠ investigator, hardware-key identities, time-bound sessions, auto-close and re-arm (ADR-0011) | sealed request/approve/grant/close records |
| Protect information about the security posture from disclosure | NIST AU-9, SC-28(1), SI-11 (error handling: no sensitive info in errors) | health-only telemetry, opaque alerts and errors (ADR-0010) | breadcrumb red-team test |
| Format-preserving pseudonyms where software needs the format | PDPC Basic Anonymisation p.36–38 | surrogates G1/G2 (ADR-0008) | surrogate test data with citations |
| Non-repudiation | NIST AU-10; CSA T8 "cryptographically signed and immutable" | Ed25519 C2SP checkpoints; caller identity | verifier |
| Audit review and reporting | NIST AU-6 | `ppe report`, alerts | report samples |
| Audit retention | NIST AU-11; PDPA s.25; PDPC §7.2–7.3 | crypto-shredding by period key (ADR-0003) | retention-run records; written rationale |
| Boundary protection; prevent exfiltration | NIST SC-7, SC-7(10) | egress allowlist so only PPE reaches providers (ADR-0001) | firewall/Squid config; doctor check |
| Transmission confidentiality | NIST SC-8 | TLS upstream; UNIX sockets locally | config |
| Key management; crypto protection | NIST SC-12, SC-13; SP 800-57; FIPS 198-1 / SP 800-224 | key hierarchy, custody tiers, HMAC-SHA-256 (ADR-0002, 0003) | key-id records; rotation logs |
| Protection at rest | NIST SC-28(1) | encrypted escrow; key files on encrypted volume | config |
| Process isolation | NIST SC-39 | detectors and auditd in own processes/accounts | systemd units |
| Monitoring | NIST SI-4 | Prometheus metrics, alerts (ADR-0004) | dashboards/rules |
| Input validation | NIST SI-10; CSA 4.1 | request schema validation; Stage 0 normalisation | tests |
| Output filtering | NIST SI-15; CSA 4.2 "output guardrails to detect PII … before it reaches the user" | reply-side scan: new PII in replies logged (restore is the user's own data) | metrics |
| Information management/retention; limit PII elements; disposal | NIST SI-12, SI-12(1), SI-12(3) | data minimisation in audit; retention job | retention table (ADR-0003) |
| De-identification | NIST SI-19 | pseudonymisation, documented as *not* anonymisation | README limits section |
| Supply chain; provenance; authenticity | NIST SR-3, SR-4, SR-11 | hash-locked deps, pinned model revisions + SHA-256, SBOM, release provenance | CI artefacts |
| Privacy risk examined and documented | NIST AI 600-1 / AI RMF MEASURE 2.10 | bench report per release | bench report |
| GAI risks: data privacy, information security | NIST AI 600-1 | whole package | controls mapping (this file) |
| Protection obligation | PDPA s.24; PDPC GenAI §9.3 | the safeguard itself | deployer's assessment cites PPE |
| Written policy on prompt data; scan prompts; restrict prompt-log access | PDPC GenAI §9.4 (HR chatbot example) | `policy-template.md`; detection; operator-only audit | deployer policy |
| Stricter handling for sensitive classes | PDPC GenAI §9.5 | `special` class → keep local (ADR-0005 Stage 3b) | policy |
| Upstream safeguards + detection-rate metrics disclosed | PDPC GenAI §8.3 | published bench metrics | bench report |
| Pseudonyms robust, keys protected, incident handling | PDPC Basic Anonymisation p.25, 31–38 | HMAC tokens; custody tiers; incident playbook (ADR-0003) | playbook |
| Breach notification assessment | PDPA s.26D | incident playbook classification | playbook |
| Single enforcement point; DLP on outgoing traffic; SIEM | CSA Addendum §4.2 (p.33) | egress guard; SIEM projection (ADR-0004, 0006) | config |
| Input guardrails detect PII; output guardrails | CSA Addendum 4.1, 4.2 | Stages 0–3; reply scan | bench |
| Tamper-evident audit logs; request ids across calls | CSA Baseline Agentic Architecture | audit chain; `req_id`, `conv` | verifier |
| Pseudonymisation domain; log reverse application; rate-limit | EDPB 01/2025 | provider inside domain, keys outside; lookups audited + rate-limited | lookup records |
| Document-randomised pseudonyms | ENISA 2019 | per-conversation scope (ADR-0002) | design doc |
| Tokenisation to sanitise sensitive information | OWASP LLM02:2025 | core transform | — |
| Inventory of PII | NIST PM-5(1) | observation plane: distinct identifiers per class/zone/source (ADR-0007) | exposure ledger |
| Information location; automated location tools | NIST CM-12, CM-12(1) | sensors at sources and model legs | coverage report |
| Data action mapping | NIST CM-13 | lineage from digests: source → loopback → cloud | ledger lineage view |
| Track new data sources and safeguard them | PDPC GenAI §9.3 | new-sensitive-source alert (ADR-0007) | alert records |
| Purpose limitation | PDPC GenAI §9.2; NIST PT-3 | declared `data_classes` per Gent vs observed | alert records |
| Every request and answer scanned | CSA Addendum §4.2 (p.33) | observation on every leg + enforcement on cloud leg | coverage figure |
| Identify and anonymise confidential data in input and output | IMDA PETs for GenAI Annex A | core | — |

## MAS Guidelines on AI Risk Management (7 Oct 2026; effective 7 Oct 2027) — added 2026-10-09

See [sources/mas-ai-risk-management.md](sources/mas-ai-risk-management.md). Guidelines, not a Notice;
applied proportionately to risk materiality.

| Requirement | Source | PPE feature | Evidence |
|---|---|---|---|
| Prohibit confidential/client information in public AI tools (basic tier minimum) | MAS AIRG §2.5(b); fn 22; Response §6.7 | egress guard: detectors, swap/restore, keep-local, block (ADR-0002, 0005, 0006) | policy file; `ppe verify`; bench per class |
| Data and cybersecurity controls even for low-materiality copilots | MAS AIRG §2.2(b) fn 12 | same; profiles `personal`/`team` | `ppe explain` knob report |
| Mitigate unidentified / shadow AI with technical controls (network monitoring, DLP) | MAS AIRG §4.4 fn 22; Response §6.7 | provider domains reachable only through PPE (ADR-0001, 0006); observation plane (ADR-0007) | Squid/firewall config; coverage report |
| Data classification guiding use of data in AI | MAS AIRG §5.4(d) | data classes, zones, special classes; restricted zone + labels (ADR-0013) | policy file; inventory |
| Secure the inputs and outputs of AI; data protection | MAS AIRG §5.4(e) | swap/restore, sealed audit (ADR-0002, 0010) | unit/property tests |
| Prevent leakage of sensitive data via prompt injection | MAS Response §10.8; AIRG §1.10(a)(b) | ratchet rule (ADR-0005); sticky labels, outward-action checks, canaries (ADR-0013) | `ppe verify --restricted` |
| Test guardrail effectiveness incl. data leakage | MAS AIRG §5.15 fn 46; §5.22(b) | `ppe bench` (detection, restore), conformance suite | bench reports |
| DLP and logging operational before go-live | MAS AIRG §5.16(a), §5.22(a) | `ppe verify`, `ppe doctor` | verify/doctor report |
| Third-party plugins/APIs: restrict data exposure | MAS AIRG §5.16(c) | egress guard on every cloud call | config |
| Monitor agent information flows, actions, tools used | MAS AIRG §5.23(a); Response §12.8 | observation plane + sensors (ADR-0007); outward-action hook (ADR-0013) | sealed ledger; coverage |
| Access to AI systems/config controlled and logged; prompt/response logging may be considered | MAS AIRG §5.23(d); Response §10.45 | sealed audit (ADR-0010); prompt capture as adopter knob, sealed, break-glass access (ADR-0011, 0012) — **to design** | sealed records |
| Agent identifiers, tool access and guardrails in the AI inventory | MAS AIRG §4.7 fn 25 | export of PPE config/manifest (models, zones, data classes, guardrails) — **to design** | export file |
| Kill switch / override for high-risk AI | MAS AIRG §5.3, §5.23(b) | `on_error` fail-closed; block-all profile switch — **to design as an explicit control** | runbook + test |

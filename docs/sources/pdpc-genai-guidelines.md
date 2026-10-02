# PDPC — Advisory Guidelines on Use of Personal Data in Generative AI (20 Jul 2026)

Final version, advisory ("not legally binding", §1.5; the PDPA prevails). Consultation draft 2 Jun
2026, closed 1 Jul 2026. Parts I–II (scraping, consent for training) are out of scope for us;
Part III (deployment) is the relevant part. Paragraph numbers below are the final version's.

## Roles (§6–9)

- **Model Provider** (§7): makes models available. When it runs inference for downstream users it is
  a **data intermediary** (§7.4): Protection Obligation (s.24) and Retention Limitation.
  §7.5: good practice to document access controls, "data residency and retention policies and
  incident response and data breach procedures".
- Footnote 19 (new in final): **open-weight** Model Providers without access to downstream personal
  data "are not subject to PDPA obligations in respect of that data".
- **System Provider** (§8): builds systems; data intermediary when processing for deployers.
  §8.3: share "input and output filters, privacy enhancing technologies", "Testing and performance
  metrics (e.g. likelihood of data leakage)", incident procedures.
  Example: legal summarisation API documents "input redaction filters" and "metrics related to data
  leakage, including the rate at which personal identifiers are detected and redacted".
- **System Deployer** (§9): "bear primary responsibility" (§9.1); must have "sufficient information on
  upstream safeguards to conduct a holistic assessment".
- §6.3 (new in final): one organisation may hold several roles; needs policies for each.

## Deployer obligations that this package serves

- §9.2 Purpose limitation: be "disciplined about specifying the intended purpose of processing and
  amount of personal data required".
- §9.3 Protection: covers "end-user prompts, inputs and generated outputs, agent or tool activity
  data, internal enterprise data"; "track and designate responsibilities over new data sources and
  implement corresponding safeguards"; educate users on which personal data may be input.
- §9.4 Written policies, ideally published. **Example (HR chatbot)**: guidelines on personal data
  allowed in prompts; "Implements measures to scan prompts for common personal identifiers and limit
  access to prompt logs to authorised maintenance personnel"; documented governance.
- §9.5 Agentic systems: review safeguards regularly; "be transparent about the privacy-utility
  trade-offs". **Example (sales agent)**: role-based limits on file and network access; "data
  classification systems that tag personal data of a more sensitive nature and requiring stricter
  handling"; escalation to humans for high-risk tasks.
- §7.2–7.3 Retention (applies to deployers too): cease retention or "remove the means by which
  personal data can be associated with particular individuals"; a retention policy with rationale.

## Consultation response (§4.3–4.5)

Respondents raised agent risks: persistent memory, disclosure through connectors and tools, unclear
multi-agent responsibility. PDPC: "a comprehensive treatment of agent-specific data issues ... is
beyond the scope of the Guidelines. These issues will be the subject of separate study and guidance."

## Draft → final (Part III)

Added §6.3 (multiple roles), footnote 19 (open weights), incident procedures in §7.5/§8.3, and in
§9.5 "access to external tools and systems" and "be transparent about" the trade-offs. Otherwise
unchanged.

## Implications

1. The deployer (Kent's operator) owns the obligation; this package is a safeguard the deployer can
   point to under §9.3–9.5, and a System Provider disclosure under §8.3.
2. Ship **measured detection rates** (per entity class, on a synthetic corpus) — §8.3 names that
   metric.
3. Ship a **written policy template** (what may go in prompts, which classes are masked / kept local /
   blocked) — §9.4.
4. **Data classes with stricter handling** (keep local instead of mask) — §9.5.
5. Restrict and log access to anything prompt-derived (audit records, forensic lookup) — §9.4.
6. Retention policy for audit records, with rationale; key deletion ends linkability — §7.2–7.3.
7. Local open-weight tiers: no upstream intermediary at all (fn 19) — the "keep local" action moves
   data to the case with the fewest parties.
8. Caveat (PDPA s.4(1)(a), from memory): individuals acting in a personal or domestic capacity are
   outside the PDPA; obligations bite on organisational deployments.

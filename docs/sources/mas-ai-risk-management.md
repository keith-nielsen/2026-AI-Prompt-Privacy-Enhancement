# MAS — Guidelines on Artificial Intelligence Risk Management (7 Oct 2026)

Issued by the Monetary Authority of Singapore on **7 October 2026** with a Response to Feedback; the
consultation paper was published 13 Nov 2025 (closed 31 Jan 2026). Guidelines (not a Notice): MAS
supervisory expectations for **all financial institutions** (as defined in FSMA 2022 s.2; 46 FI
types listed on the MAS page) and **all forms of AI**, explicitly including Generative AI and AI
agents (§1.5). Applies on a group basis for locally incorporated FIs under consolidated supervision
or owning critical information infrastructure (§1.2). Paragraph numbers below are the final text's.

Read: final guidelines in full; Response to Feedback §1–3, §6, §10 (data, cyber, auditability),
§12–13; consultation paper compared on key terms only. Annex B (325 pages of public submissions)
stored, not read. The press release was read through a summarising fetch (the MAS site served a
maintenance page to direct downloads); the guideline and response PDFs were read in full text.

## Timing (§1.8; Response §13)

- Takes effect **7 Oct 2027**. Sections 3–4 (oversight; identification, inventory, risk materiality)
  from 7 Oct 2027; Sections 5–6 (life-cycle controls; capability and capacity) **by 7 Oct 2028**.
- Response §13.5: high-risk use cases should get life-cycle controls "as soon as possible, and not
  delay application until the end of the 24-month transition period".
- Change from the consultation: a single 12-month transition was proposed (CP Question 10).

## Proportionality and the "basic governance" tier (§2.1–2.5) — new in the final text

- §2.3: an FI may apply only basic policies if poor performance or unavailability of its AI "is
  unlikely to have a material adverse impact on the FI, its customers or other stakeholders".
- §2.4 examples: drafting/rephrasing customer e-mails, summarising documents or meeting notes for
  internal use, initial document review, formulas/charts, image generation, internal-resource
  chatbots (footnote 13: humans review outputs).
- §2.5(b) minimum: "permitted and prohibited uses of AI (e.g., **prohibitions on inputting
  confidential, proprietary or client information into public AI tools**), together with effective
  human oversight". Also (c) an approved list of AI tools; (e) regular compliance checks.
- Footnote 12: even for low-materiality copilots, "AI life cycle controls relating to **data
  management, safety and cybersecurity** would be relevant and should be applied in a proportionate
  manner".
- Response §3.14: FIs not yet using AI should still have policies on whether and how staff may use
  AI, "to manage risks arising from any unauthorised use of AI (such as 'shadow AI')".

## Risks named (§1.9–1.11)

- §1.10(b) **Privacy risks**: "leakage of confidential or customer data due to the use of
  third-party Generative AI services". (a) Security: prompt injection, data poisoning.
  (f) Human-factor: shadow AI, automation bias.
- §1.11 Agents: "Compromised AI agents with access to internal systems and external tools could be
  used to **exfiltrate sensitive data** or execute malicious commands at scale".

## Identification and inventory (§4.2–4.9)

- §4.4 + fn 22: where all AI use cannot be identified (embedded AI, shadow AI), mitigate, e.g.
  prohibitions on inputting client information into public AI tools, "or uplifting technical
  controls (e.g., network monitoring, **data loss prevention**) to detect unauthorised use of AI".
  Response §6.7: "implementing technical controls to restrict access to, or the sharing of sensitive
  information with, public AI tools where appropriate; monitoring for unauthorised AI use".
- §4.7 inventory attributes include "data used", dependencies, scope of use. Fn 25 (new): for AI
  agents, "agent-specific identifiers, information on the tools and systems the agent can access, its
  components, and the guardrails imposed".
- §4.12(a) risk materiality: "The nature and sensitivity of the data processed by the AI system or
  model should also be considered."

## Life-cycle controls relevant to PPE (§5)

- §5.4(d) **Data classification** "to guide appropriate use of data in an AI use case … taking into
  account criticality and sensitivity". (e) **Data security**: "securing the inputs and outputs of
  the AI use case". (f) **Data privacy** per PDPC guidance (fn 30 cites the PDPC GenAI guidelines —
  see [pdpc-genai-guidelines.md](pdpc-genai-guidelines.md)). Response §10.6: privacy and consent stay
  governed by PDPC/MAS rules, "irrespective of whether data processing … is conducted in Singapore or
  cross-border". Response §10.8: "Additional controls should also be applied to address data security
  risks specific to Generative AI, such as preventing inadvertent leakage of sensitive data through
  prompt injection."
- §5.10–5.11 **Third-party AI**: the FI keeps primary accountability; consider transparency,
  supply chain (model provenance), concentration, change notification, contingency, legal terms
  ("data protection, the right to audit").
- §5.15 + fn 46: testing of GenAI should cover "data leakages or disclosures, and vulnerability to
  adversarial attacks"; guardrail effectiveness must be tested.
- §5.16(a) deployment controls include "input validation, API authentication, encryption, and **data
  loss prevention**"; (c) third-party plugins/APIs: "restrict data exposure".
- §5.22(a) pre-go-live checklist: "encryption, **data loss prevention**, firewalls, access
  restrictions and logging, are operational and correctly configured"; (b) red teaming, adversarial
  tests, input validation, anomaly detection.
- §5.23(a) monitoring "information flow and decision-making paths … such as reasoning processes,
  actions taken, tools used" (agents; Response §12.8). (b) kill switches / override for high-risk AI.
  (d) access to AI systems and configuration "strictly controlled and logged"; "**logging prompts and
  model responses**" may be considered for GenAI and agents (new; Response §10.45: FI decides
  necessity by risk materiality).
- §5.25 change management with version control and rollback; §5.26 decommissioning incl. data
  retention.

## Agents (Response §12)

- §12.3: MAS "does not intend to restrict the use of any specific AI technology … provided that the
  risks are adequately addressed".
- §12.4/12.9: agentic AI risks "warrant dedicated attention"; IMDA's Model AI Governance Framework
  for Agentic AI is the interim reference; MAS will consult separately on agent-specific guidance.
- §12.7: no mandated testing techniques or minimum controls "at this time".

## Implications for this package

1. **Direct fit.** An FI using cloud LLMs (including staff coding agents such as Claude Code) is a
   third-party GenAI user. PPE implements the technical controls MAS names: DLP on inputs to
   third-party/public AI (§2.5(b), fn 22, §5.16(a), §5.22(a)), data classification guiding use
   (§5.4(d) → zones, special classes, ADR-0013 restricted zone), securing inputs and outputs
   (§5.4(e) → swap/restore), and leakage testing of guardrails (§5.15 → `ppe bench`/`ppe verify`).
2. **Even the basic tier needs it.** A low-materiality copilot still needs proportionate data and
   cybersecurity controls (fn 12) and a prohibition on client data in public AI tools — PPE turns
   that policy into an enforced, evidenced control.
3. **Agents.** §1.11 names exfiltration by compromised agents; §5.23(a) asks for monitoring of tools
   and actions; fn 25 asks for agent identifiers, tool access and guardrails in the inventory. This
   matches ADR-0007 (observation plane) and ADR-0013 (sticky labels, outward-action checks,
   canaries). The `ppe verify --restricted` report is the kind of guardrail-effectiveness evidence
   §5.15 asks for.
4. **Prompt logging vs. our minimisation.** §5.23(d) suggests logging prompts and responses for
   GenAI/agents; ADR-0010 deliberately keeps no readable content. Reconcile as an adopter knob
   (ADR-0012): sealed prompt/response capture with break-glass access (ADR-0011) gives the
   auditability without breadcrumbs. Note: MAS leaves necessity to the FI's risk assessment.
5. **Inventory attributes.** PPE's own config/manifest can export what §4.7/fn 25 need for the FI's
   AI inventory (models used, data classes allowed per zone, tools/guardrails), so adopters can link
   PPE to their inventory.
6. **Timing.** FI adopters must have Sections 3–4 in place by 7 Oct 2027 and life-cycle controls by
   7 Oct 2028 (sooner for high-risk use) — useful for roadmap messaging; v0.1.0 is not needed for §3–4.

## Linked references not yet read

- MAS Information Paper on Cyber Risks Associated with Generative AI (fn 9):
  https://www.mas.gov.sg/regulation/circulars/cyber-risks-associated-with-generative-artificial-intelligence
- IMDA Model AI Governance Framework for Agentic AI (fn 11; Response §12.9):
  https://www.imda.gov.sg/-/media/imda/files/about/emerging-tech-and-research/artificial-intelligence/mgf-for-agentic-ai.pdf
- IMDA Starter Kit for Testing LLM-Based Applications for Safety and Reliability (fn 43, 46):
  https://www.imda.gov.sg/-/media/imda/files/about/emerging-tech-and-research/artificial-intelligence/large-language-model-starter-kit.pdf
- MAS Technology Risk Management Guidelines (fn 47).
- PDPC Advisory Guidelines on Personal Data in AI Recommendation and Decision Systems (fn 30).

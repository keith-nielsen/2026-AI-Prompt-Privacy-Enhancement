# CSA (Singapore) — Securing Agentic AI, Addendum to the Guidelines and Companion Guide on Securing AI Systems

Final v1.0 issued 17 Jun 2026 (consultation 22 Oct – 31 Dec 2025). The draft was read first; the
**final was read on 2026-10-02** (section below) and the controls used here are unchanged. Voluntary
guidance.

## What it says (draft)

- Enterprise-scale controls: "a middleware providing a single enforcement plane where identity and
  access management ..., guardrails (input and output), data loss prevention, and policy controls
  apply consistently", routing "all agent-initiated calls ... through a central gateway"; middleware
  logs streamed to a SIEM.
- Threat tables: "Sensitive information disclosure → Automated PII redaction. Fine-grained access
  control. Context-aware guardrails." "Lack of compliance on sensitive data → Data minimisation.
  Pseudonymisation/Anonymisation." "Manipulation of logging data → Secure logging infrastructure.
  Log integrity monitoring."
- Logging: "end-to-end distributed tracing with unique request IDs across all agents and tool calls";
  "immutable, tamper-evident audit logs that capture prompts, responses, and tool invocations"; "If
  greater integrity is needed, AI-generated logs can be cryptographically signed and immutable."
- Agents storing sensitive data from prior interactions: encrypt at rest, fine-grained access,
  audit logs.

## Final v1.0 (17 Jun 2026) — read 2026-10-02

Local copy `pdf/csa-securing-agentic-ai-addendum-final-2026-06-17.pdf` (106 pages). Checked against
the draft quotes above; numbering **unchanged** for the controls we use (page numbers approximate,
from text extraction):

- §4.2 "Implementing Controls at Enterprise-scale" (p.33): "a single enforcement point where all
  security rules are applied consistently"; "Data loss prevention – Automated scans of outgoing traffic
  mitigate the risk of leaking sensitive company information"; "logs from the middleware should be
  streamed into a SIEM for SOC monitoring".
- Control **4.1 Validate inputs** (p.70): "Implement input guardrails to detect personally
  identifiable information in the content" (risk: "Exposure of personally identifiable information
  from retrieved content", component "Operational: File & Data Management"); also "Implement input
  sanitisation measures or limit inputs to conventional ASCII characters only".
- Control **4.2 Validate outputs** (p.70–71): "Implement output guardrails to detect personally
  identifiable information in the LLM's outputs before it reaches the user."
- Baseline Agentic Architecture (p.53, p.72): "end-to-end distributed tracing with unique request IDs
  … across all agents and tool calls"; "immutable, tamper-evident audit logs that capture prompts,
  responses, and tool invocations".
- Threat T8 Repudiation (p.87): "Require AI-generated logs to be cryptographically signed and
  immutable for regulatory compliance."
- A2A/MCP threat tables (p.~95): "Sensitive information disclosure → Automated PII redaction.
  Fine-grained access control. Context-aware guardrails."; "Lack of compliance on sensitive data →
  Data minimisation. Pseudonymisation/Anonymisation"; "Manipulation of logging data → Secure logging
  infrastructure. Log integrity monitoring."

Note the CSA wording "capture prompts, responses" — PPE meets it with tokens + keyed digests, not
plaintext (see Implications 2).

## Kent's audit mapping (2026-09-28 review)

Addendum 4.1 "Validate inputs (guardrails, schema validation, sanitisation, PII detection)" = **Gap**;
4.2 "Validate outputs (... PII guardrails ...)" = Partial; finding **F-08 (High)**: "no DLP or
redaction before prompts leave the host"; recommended fix: "a pre-call guardrail that detects and
redacts PII and secrets, and blocks classified content from cloud tiers (a LiteLLM guardrail hook or
a `kent_gateway` pre-call)".

## Implications

1. A gateway plugin is the architecture CSA describes (single enforcement plane).
2. Tension with EDPB (logs full of personal data are a risk): log **tokens and keyed digests**, never
   plaintext — satisfies "capture prompts" for audit without building a personal-data store.
3. Audit records carry request id and trace/conversation id; append-only, hash-chained, optionally
   signed.
4. Closes F-08 for Kent (with the provider assessment still owed separately).

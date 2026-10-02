# EU — EDPB LLM report (Apr 2025), EDPB Guidelines 01/2025 on Pseudonymisation, ENISA (2019)

## EDPB support pool — AI Privacy Risks & Mitigations: LLMs (read, relevant parts)

Mostly provider-side. Relevant risks: "Unauthorized access to logs: Logs containing user inputs and
outputs could be accessed by unauthorized personnel or exploited in the event of a data breach";
"Data aggregation risks" from logs over time; "Third-party exposure" through external cloud
processing; missing retention policies. Mitigations: minimise logging, encrypt log data, monitor log
access, retention limits; "redact sensitive identifiers in outputs"; "Use anonymization and
pseudonymization tools".

## EDPB Guidelines 01/2025 on Pseudonymisation (summary only — primary text still to read)

- "Pseudonymised data remains personal data."
- **Pseudonymisation domain**: parties that see only pseudonymised data and have no access to the
  "additional information" (keys, tables). Here: the cloud provider is inside the domain; the gateway
  holds the additional information.
- Techniques: lookup tables or cryptographic (MAC with secret key, encryption).
- Keys ideally in an HSM.
- "Rate limiting and logging of the execution of the pseudonymising transformation and its reverse
  application"; authorised personnel only.

## ENISA — Pseudonymisation techniques and best practices (summary only)

Techniques: counter, random generator, hash, MAC, encryption. Policies: **deterministic** (same
input → same pseudonym everywhere), **document-randomised** (same within one document, different
across documents), **fully randomised**. Risk-based choice.

## Implications

1. Per-conversation tokens = ENISA's document-randomised policy.
2. Log every masking and every forensic lookup (EDPB "reverse application"); rate-limit lookups.
3. Key custody outside the agent's reach; HSM/TPM as an optional hardening tier.
4. Output-side scanning (replies) is in scope, not just inputs.

# IMDA / PDPC — PETs Adoption Guide (file Jan 2026, "draft for industry consult") and PETs for Generative AI (Jul 2024)

## PETs Adoption Guide (40 pages)

Mostly data-sharing PETs: differential privacy, homomorphic encryption, synthetic data, federated
learning, secure multi-party computation, trusted execution environments (TEEs), zero-knowledge
proofs. Annex 2 is an implementation checklist.

- **LLM-based detection accepted** (case 1.3.3, Grab): automated tagging and anonymisation "via a large
  language model (LLM)-based solution", accepted with "multi-layered data protection practices" and
  "periodic reviews to assess adequacy of techniques"; where direct and indirect identifiers are
  removed the record "can be considered anonymised".
- TEE common application: "Processing user queries on large language models (LLMs) privately"
  (confidential inference at the provider).
- Annex 2, "Practical Guidance on Handling Identifiers":
  - remove direct identifiers and verify they are absent from the output;
  - "Encrypt identifiers and securely manage encryption keys, ensuring proper and secure rotation";
  - hashing: add "salts" to resist precomputed tables;
  - "retain mappings only if needed for a specific purpose"; if kept, "securely stored, preferably
    out-of-band and away from the hidden identifiers";
  - hidden forms "should never be linkable to associated indirect identifiers".
- Annex 2, implementation: assurance testing (unit, integration, VAPT); "Use synthetic data ... for
  testing, instead of using production data"; post-implementation monitoring, annual review,
  re-identification reassessment after changes, documentation, proper disposal.

## PETs Sandbox Expansion — Use of PETs for Generative AI (4 pages)

- Prompts and outputs "can include anything, including confidential data", which "may be stored and
  may be inadvertently used to further train" models.
- "While not traditionally considered PETs, Gen AI can be used to identify and flag personal data,
  which can then be removed or obfuscated."
- Annex A, use phase: "Encrypted Inferences using SMPC", "Conducting Inferences in a TEE", "Gen AI
  PETs solutions to identify and anonymise CD [confidential data] in input and output".
- Calls PETs for generative AI "nascent"; invites sandbox use cases.

## Implications

1. The package is exactly the "identify and anonymise CD in input and output" archetype IMDA names —
   aligned with policy direction, but no settled standard yet. A PET Sandbox application is an
   option once it works.
2. A local model as detector (Stage 3) is an accepted approach if reviewed periodically.
3. Separation: key (gateway account) / audit records (operator-only store) / tokens (provider) — the
   "out-of-band" rule.
4. Test corpus is synthetic only (also suits a public repo).
5. Confidential inference (TEE) is the stronger PET for the cloud leg; it depends on the provider, so
   the docs list it under the deployer's provider assessment, not as a package feature.

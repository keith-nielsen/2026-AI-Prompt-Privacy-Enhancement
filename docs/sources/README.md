# Source material

Primary documents read for the design, retrieved 2026-10-02. Local copies sit in `pdf/` (git-ignored:
third-party documents are linked, not redistributed); the SHA-256 lets anyone confirm they read the
same file. Each note gives what the document says (quoted where it matters) and what it implies for
this package. "Read" means the primary text was read; "summary" means only secondary coverage was.

| # | Document | Issuer, date | Status | Read | Note |
|---|---|---|---|---|---|
| 1 | Advisory Guidelines on Use of Personal Data in Generative AI | PDPC (SG), 20 Jul 2026 | final, advisory | read | [pdpc-genai-guidelines.md](pdpc-genai-guidelines.md) |
| 2 | Response to Feedback on the Public Consultation (same guidelines) | PDPC, 20 Jul 2026 | final | read (§4–5) | same note |
| 3 | Proposed Advisory Guidelines (consultation draft) | PDPC, 2 Jun 2026 | superseded | read | same note (diff) |
| 4 | Guide to Basic Anonymisation (updated) | PDPC, 24 Jul 2024 | final | read (relevant parts) | [pdpc-basic-anonymisation.md](pdpc-basic-anonymisation.md) |
| 5 | Privacy Enhancing Technologies Adoption Guide | IMDA with PDPC, file dated Jan 2026 | marked "draft for industry consult" | read (relevant parts) | [imda-pets.md](imda-pets.md) |
| 6 | PETs Sandbox Expansion — Use of PETs for Generative AI | IMDA, Jul 2024 | final | read | same note |
| 7 | Securing Agentic AI — Addendum to the Guidelines on Securing AI Systems | CSA (SG); final v1.0 17 Jun 2026 | final | read (draft, then final 2026-10-02) | [csa-agentic-addendum.md](csa-agentic-addendum.md) |
| 8 | AI Privacy Risks & Mitigations — Large Language Models | EDPB support pool (I. Barberá), Apr 2025 | expert report | read (relevant parts) | [eu-edpb-enisa.md](eu-edpb-enisa.md) |
| 9 | Guidelines 01/2025 on Pseudonymisation | EDPB, 16 Jan 2025 | consultation version | summary | same note |
| 10 | Pseudonymisation techniques and best practices | ENISA, 2019 | final | summary | same note |
| 11 | LLM02:2025 Sensitive Information Disclosure | OWASP GenAI | final | read | [owasp-llm02.md](owasp-llm02.md) |
| 12 | LiteLLM 1.100.1 source (guardrail and callback hooks, Presidio hook) | BerriAI | code as installed | read | [litellm-hooks.md](litellm-hooks.md) |
| 13 | Kent harness: 2026-09-28 external security review (F-08) and gateway | this project's sibling | internal | read | [kent-context.md](kent-context.md) |
| 14 | NIST SP 800-53r5 (AC-4 family etc.), SP 800-224 ipd, 800-38G r1 2pd, 800-57, 800-92r1 ipd, AI 600-1, PF 1.1 draft | NIST | mixed (see note) | status checked; controls from catalogue reproductions | [nist.md](nist.md) |
| 15 | llama.cpp `parallel-decision` branch (README, engine, server handler) | thecodacus, Sep 2026 | code | read (not built) | [parallel-decision.md](parallel-decision.md) |
| 16 | PII detector model cards and papers (GLiNER2-PII, OpenAI Privacy Filter, NVIDIA GLiNER-PII, GLiNER Guard, PIIBench, evasion study) | various, 2025–2026 | cards / preprints | read | [detector-models.md](detector-models.md) |
| 17 | Claude Code gateway compatibility guide + LLM gateway page | Anthropic docs | current | read | [claude-code-gateway.md](claude-code-gateway.md) |
| 18 | LiteLLM 2026 security events, v1.102.0 notes, 1.100.1 `apply_guardrail` | BerriAI / OSV / press | — | read | [litellm-2026.md](litellm-2026.md) |
| 19 | Prior-art local PII proxies (PasteGuard, Kiji, occludra, pii-proxy, llm-guard) | GitHub | — | metadata / READMEs | [prior-art.md](prior-art.md) |

## SHA-256 of the local copies (`pdf/`)

```
37228d2e2dc93ed1dd8963f2d207931e818317d224f1f7088b5855a9c1ff5c93  csa-securing-agentic-ai-addendum-consultation-draft.pdf
f74e4bbe0718dbbcbef85ccf283cc8417960adf50d12ba337ab9d285408b87fe  edpb-ai-privacy-risks-mitigations-llms-2025-04.pdf
9718d82f85a88a3bc3f59fa773c13ed9987f39fb5347472313d1aafb0922f204  imda-pets-adoption-guide-draft-2026-01.pdf
e5ad6cb530952e21beebf74cad2a8403819d930cfc3270037f3497353819f888  imda-pets-for-generative-ai-2024-07.pdf
c51c682d125294abb11a1378963f693eb7c49d59522758d2b8a234c79ac10c02  pdpc-genai-consultation-response-2026-07-20.pdf
de6e09e378c5137ac11dac4188a3e5970db43dcb5e5c8cb17d74c8e37825a7af  pdpc-genai-guidelines-2026-07-20.pdf
929a8774122ababced31fe6c8dc06f7da3c856a24b1d0862c1de595b19b7b591  pdpc-genai-guidelines-proposed-2026-06-02.pdf
1250cac479c63aa0883a89685fe535fcc1f4691940bdd4a7a89e09637c56403f  pdpc-guide-to-basic-anonymisation-2024-07-24.pdf
6bb2f5a422b3ce2b6a6f8ebc64cb664d69dd08ad58a8b99f99cfb43f8676cf2b  csa-securing-agentic-ai-addendum-final-2026-06-17.pdf
```

## URLs

1. https://files.app.optical.gov.sg/pdpc/production/assets/143cb9d4-532e-4cca-9a77-bcc0415ca294.pdf
2. https://files.app.optical.gov.sg/pdpc/production/assets/e42ea070-3bf2-43f7-b1bb-ba3ad22e223d.pdf
3. https://files.app.optical.gov.sg/pdpc/production/assets/ceb45ef8-294d-4b45-be35-e884d578fd8d.pdf
4. https://www.pdpc.gov.sg/-/media/files/pdpc/pdf-files/advisory-guidelines/guide-to-basic-anonymisation-(updated-24-july-2024).pdf
5. https://www.imda.gov.sg/-/media/imda/files/programme/pet-sandbox/pets-adoption-guide.pdf
6. https://www.imda.gov.sg/-/media/imda/files/programme/pet-sandbox/pets-for-generative-ai.pdf
7. https://www.csa.gov.sg/resources/publications/addendum-on-securing-ai-systems/ (final; PDF link on that page); draft copy: https://isomer-user-content.by.gov.sg/36/703ff9fe-9db1-4e09-98c2-89e3d7007ef0/Draft%20Addendum%20on%20Securing%20Agentic%20AI%20[For%20Public%20Consultation].pdf
8. https://edpb.europa.eu/system/files/2025-04/ai-privacy-risks-and-mitigations-in-llms.pdf
9. https://www.edpb.europa.eu/our-work-tools/documents/public-consultations/2025/guidelines-012025-pseudonymisation_en
10. https://www.enisa.europa.eu/publications/pseudonymisation-techniques-and-best-practices
11. https://genai.owasp.org/llmrisk/llm02/

## Still to read

- ~~CSA addendum final text~~ — read 2026-10-02; controls 4.1/4.2 unchanged.
- NIST SP 800-53r5 primary catalogue text for the controls in `nist.md` (cited from reproductions).
- OpenAI Privacy Filter model card PDF (cdn.openai.com) — blog page returned 403 to the fetcher.
- EDPB Guidelines 01/2025 and ENISA 2019 primary text (only summaries so far).
- PDPC Advisory Guidelines on Key Concepts in the PDPA (§12.84–12.94 publicly available; §18.5–18.8
  retention) and on AI Recommendation and Decision Systems (2024), both cited by #1.
- PDPA itself: s.4(1)(a) (individuals acting in a personal or domestic capacity), s.24, s.25, Part 6A
  (breach notification). Quoted from memory so far, not checked.
- Anthropic's data retention / residency / zero-retention terms (input to the deployer's §9.1
  assessment; not this package's job, but the docs should point to it).

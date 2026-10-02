# OWASP — LLM02:2025 Sensitive Information Disclosure

Mitigations listed (genai.owasp.org/llmrisk/llm02):

- "Implement tokenization to preprocess and sanitize sensitive information. Techniques like pattern
  matching can detect and redact confidential content before processing."
- Data sanitisation; input validation; least-privilege access; restrict data sources; differential
  privacy; homomorphic encryption; federated learning; transparency on retention and use; user
  education; protect system preambles.

## Implications

Generic, but names the technique. The README's threat model cites LLM02 as the primary risk addressed
and LLM01 (prompt injection) only as a secondary signal.

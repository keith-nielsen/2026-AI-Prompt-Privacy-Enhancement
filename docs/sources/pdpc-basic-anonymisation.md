# PDPC — Guide to Basic Anonymisation (updated 24 Jul 2024)

60 pages; five-step process (know your data → de-identify → apply techniques → compute risk → manage
risk) and a technique annex. Page numbers are the guide's.

## De-identified is not anonymised

- "The de-identified data is still personal data as it is likely to be easily re-identifiable.
  However, it is still good practice to de-identify the data as it provides an additional layer of
  protection." (use case "internal data sharing (de-identified data)", p.16)
- Anonymised = direct **and** indirect identifiers treated and re-identification risk assessed
  (k-anonymity etc.).
- Reversibility (p.11): anonymisation is normally irreversible; where the organisation can recreate
  the original, the process is "reversible".

## Pseudonymisation (annex, p.36–38)

- "replacement of identifying data with made-up values". Irreversible when originals are disposed of
  and the process is non-repeatable; reversible "by the owner of the original data" when originals
  are kept.
- "Persistent pseudonyms allow linking ... However, different pseudonyms may be used to represent the
  same individual in different datasets to prevent linking of the different datasets."
- Step 2 (p.~25): pseudonyms "should be unique for each unique direct identifier" and "robust (i.e.
  not be reversible by unauthorised parties through guessing or computing the original direct
  identifier values from the pseudonyms)".
- Tips: for reversible pseudonyms "the identity mapping table cannot be shared with the recipient";
  hash/encryption keys and salts "must be securely protected ... a leak ... could result in a data
  breach by enabling ... pre-computed tables to infer the data that was hashed (especially for data
  that follows pre-determined formats such as in NRICs)"; review algorithm and key length
  periodically; format-preserving pseudonyms (or FPE) where software needs the original format.
- "relying on a proprietary or 'secret' reversal process (with or without a key) has a greater risk of
  being decoded and broken compared to using a standard key-based encryption or hashing."
- Double coding: a second linking table held by a trusted third party.

## Incident management (p.31–32)

- De-identified data **and** mapping table lost → "akin to the breach of personal data"; assess
  notifiability.
- De-identified data only → assess; de-identification "could be considered part of the protection
  mechanisms".
- Mapping table only → "not personal data", need not be reported, but "immediately generate new
  pseudonyms ... and a new identity mapping table" and investigate.

## Implications

1. Masked prompts sent to a cloud model remain personal data (indirect identifiers survive). The
   package must say so plainly: it is a protection mechanism, not anonymisation.
2. Token = standard keyed MAC (HMAC-SHA-256), never a plain hash (NRIC/passport spaces are
   enumerable) and never a home-made scheme.
3. Per-conversation tokens = "different pseudonyms in different datasets": supported.
4. The HMAC key is the "identity mapping table" equivalent: protect it like one, key id on every
   record, periodic review, rotation; **key compromise playbook** = rotate, regenerate, investigate,
   assess old tokens held by providers (enumerable for structured IDs once the key leaks).
5. No stored token → value mapping (in-memory per request only). Forensics confirms a suspected value
   via its digest; it never decodes a token. Stricter than the guide requires.
6. Prefer explicit `<TYPE_xxxx>` tokens over format-preserving fakes (fakes can be mistaken for real
   data); FPE stays an option per entity class.
7. Breach at the provider (de-identified data only): masking counts as a protection mechanism —
   the concrete value of the package in an incident report.

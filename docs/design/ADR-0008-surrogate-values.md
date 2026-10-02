# ADR-0008 — Plausible surrogate values ("dummy data") as the default swap, typed tokens opt-in

Status: **proposed** (2026-10-02). Operator direction (2026-10-02): block egress of real values and
"swap-out replace with plausible 'dummy data' for swap-back once the prompts return back to the
user's session"; surrogates for **all classes**, typed tokens as a per-class option. **Supersedes
the ADR-0002 rejection of realistic fakes**; ADR-0002's keys, scope, determinism and restore
invariants still apply. Special categories (health etc.) stay keep-local (ADR-0005 Stage 3b).

## Context

Typed tokens (`<PASSPORT_7f3a…>`) are safe and easy to restore, but they look artificial. Models
handle realistic data more naturally: they format letters, validate shapes, write code against
it. Realistic surrogates bring four risks, and the design has to address each one:

1. **A surrogate equals a real person's data** → the provider sees a real identifier wrongly attached
   to someone else's content (misattribution, possibly worse than a leak).
2. **Agents act on surrogates**: a cloud-planned tool call emails the fake address.
3. **Restore is harder**: models reformat values (`+65 9123 4567` → `91234567`) and split names
   ("Ms Tan").
4. **Surrogates collide with real text** in the conversation or reply.

## Decision

### Construction rules, strongest first

For each type, PPE uses the first construction available:

| Rank | Construction | Guarantee |
|---|---|---|
| G1 | **reserved range** set aside by a standard or regulator | never real |
| G2 | **valid format, invalid check digit** (the type has a checksum every real value satisfies) | provably never issued |
| G3 | **processor test range** (payment test BINs) | never a live account (per network/processor) |
| G4 | **pool-generated** (names, streets): plausible, drawn from locale pools | **may coincide with a real person**; residual risk, documented |

All reserved ranges below are from memory and secondary sources. **Verify each against the issuing
standard or regulator list before shipping** (CI test data file with citations).

| Type | Surrogate (default) | Rank |
|---|---|---|
| e-mail | `<given>.<family>@example.com/.net/.org` or `@<word>.example` (RFC 2606 / RFC 6761) | G1 |
| URL / domain | `*.example`, `example.com` | G1 |
| IPv4 / IPv6 | RFC 5737 TEST-NET-1/2/3 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`); RFC 3849 `2001:db8::/32` | G1 |
| phone US/CA | NANP `555-0100`–`555-0199` | G1 |
| phone UK | Ofcom drama ranges (e.g. `07700 900000–900999`, `01632 960xxx`) | G1 |
| phone AU | ACMA's published list of fictitious numbers (a list of specific numbers, e.g. `0491 570 006`, not a whole block — small pool) | G1 |
| **phone SG** | **no reserved range found** → open question to IMDA; interim: well-formed 8-digit number with a leading digit outside current allocations **if one is confirmed**, else typed token | G1? / token |
| NRIC / FIN (SG) | correct series letter and 7 digits, **wrong check letter** | G2 |
| IBAN | correct country/length/bank-code shape, **wrong mod-97 check digits** | G2 |
| payment card | test-BIN ranges with valid Luhn (G3), or a real-looking BIN with **invalid Luhn** (G2), per policy | G3 / G2 |
| UEN (SG) | wrong check character | G2 |
| passport, licence, account numbers without checksum | format-shaped, with a recognisable reserved prefix where one exists; otherwise typed token | G4 / token |
| secrets / API keys | same prefix and length, body generated, ending in `EXAMPLE` where the format allows (the AWS documentation convention); never a value that passes the issuer's checksum (GitHub token CRC) | G2 |
| person name | given + family from locale-weighted pools (SG Chinese/Malay/Indian/Eurasian, EN, EU), excluding public-figure lists and dictionary words; components mapped separately | G4 |
| street address | pool street + house number; postal code in an unallocated or wrong-format block where known | G4 |
| date of birth / personal dates | **consistent shift** per conversation: random offset of ±1–180 days from the scope key, keeping year/age band (the medical de-identification practice) | — |

Policy can force `token` for any type, or require `min_guarantee: G2` per class (anything weaker
falls back to a typed token). Shipped defaults: `G4` allowed for names/addresses (operator choice:
all classes); `hardened` profile suggests `min_guarantee: G2` for identifiers.

### Determinism (keeps ADR-0002 R3 and byte-stable history)

- Surrogate = f(type, seed) with `seed = HMAC-SHA-256(k_tok[e], "ppe/sur/v1" ‖ lp(scope) ‖ lp(type) ‖ lp(norm_v(value)))`.
  Same value in the same conversation → same surrogate on every turn.
- Collision handling, deterministic: if the surrogate equals any real value or another surrogate in
  the request, or appears literally anywhere in the conversation text, probe `seed_i = HMAC(seed, i)`
  for i = 1, 2, … . The order is first-appearance order in the conversation, which stays stable across
  turns. Compaction/truncation can reorder values; it already resets prompt caching and thinking, so
  that is accepted.
- **Name components**: map family and given names separately and consistently (real "Lim" → surrogate
  "Tan" everywhere in the scope), so "Jane Lim", "Ms Lim", "Jane" all restore. The component map is
  part of the vault.

### Restore with surrogates (extends ADR-0002 R1–R6)

- **Closed world** (R1): restore only surrogates issued in this request's vault.
- **Normalised matching per type**: phone/card/IBAN/NRIC candidates in the reply are normalised by the
  same `norm_v` and compared to issued surrogates (so a reformatted `91234567` still restores);
  e-mail case-insensitive in the domain; names matched as whole-word components, case-preserving.
- The real value is restored **in the format the model used** where the type defines one (phone
  grouping, card spacing), otherwise in its original surface form.
- **Ambiguity rule**: if a surrogate component (e.g. given name "May") also appears in the reply
  where it was not issued as a surrogate (a common word, sentence start), restore only occurrences
  in a name context (capitalised, adjacent to another issued component or a title); count others as
  `restore_ambiguous`. Surrogate pools exclude dictionary words to keep this rare.
- **Tool calls (agent risk 2)**: restore runs on tool-call arguments **before** the client or agent
  executes them, so local tools get the real value. A tool call that PPE cannot fully restore — it
  holds an issued surrogate in a form PPE can't map — is **flagged in the response**
  (`x-ppe-restore-incomplete`) and audited. Clients that execute tools themselves (Claude Code,
  Hermes) only ever see restored arguments. Tool calls that the **provider** executes server-side
  (web search, code execution in the provider's sandbox) see surrogates only. By design those never
  get real values: a server-side tool reaching a fake e-mail address hits `example.com`.
- R3 round trip, with the inverse map from real surface forms → surrogates (incl. name components).

### Telling the model (optional, policy)

`announce: none | system_note`. With `system_note`, PPE adds a short note to the *last* system block
or the first user turn ("Some personal details in this conversation are placeholders; keep them
exactly as written"). This can improve keep-as-written behaviour, but it changes the system content,
so it is set per conversation from turn 1 and never toggled mid-conversation (byte stability).
Default `none`, until the bench shows it helps.

## Consequences

- Positive: natural model behaviour on realistic data; G1/G2 constructions are provably not real for
  the identifier types where misattribution would hurt most (NRIC/FIN, IBAN, cards, e-mails, IPs);
  determinism keeps caching and thinking intact.
- Negative: names and addresses (G4) can coincide with real people, a documented residual. Restore
  is more complex (normalised and component matching) and needs a large property-test suite. SG
  phones have no known reserved range yet. A model that "validates" a G2 surrogate may comment that
  the checksum is wrong — the bench must measure how often and whether it hurts answers.
- The provider sees realistic-looking personal data that is fake. For the deployer's PDPC/EDPB
  analysis it is still pseudonymised processing (the context and indirect identifiers are real).
  The docs say so.

## Alternatives considered

- *Typed tokens default* (ADR-0002 original): kept as an opt-in per class.
- *FF1 format-preserving encryption*: realistic and reversible without a vault, but the key becomes
  a universal decoder (ADR-0002), and FF1 output can be a real, valid identifier (no G1/G2 guarantee).
  Rejected for default.
- *Random fakes without determinism*: break byte-stable history. Rejected.
</content>
</invoke>

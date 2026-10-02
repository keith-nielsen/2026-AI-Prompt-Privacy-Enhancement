# ADR-0010 — Fully sealed audit: no readable breadcrumbs; two-part decryption (machine + token)

Status: **proposed** (2026-10-02). Operator direction (2026-10-02): clear occurrence records give an
attacker "a breadcrumb … for who/what they need to compromise in order to get what they want …
attack targeting information itself". The occurrence part must be fully encrypted and "only
observable by an audit-grade decrypter", with **two-part encryption: the machine's public key + a
second part standing in for a USB key, simulated as the string `"1234"` during development**.
**Supersedes ADR-0009's clear occurrence part** (ADR-0009's sealing of value digests, offline
investigation and shredding ideas carry over). **Amends ADR-0004** (telemetry, alerts, SIEM),
**ADR-0006** (presentation), **ADR-0007** (ledger, alerts, coverage).

> **Extended by [ADR-0011](ADR-0011-break-glass-release.md) (2026-10-02):** live, on-the-fly decryption
> for a security operator through a two-approver, time-bound break-glass release on a decryption
> broker; keys stay in hardware and are never handed to anyone.

## Principle

> Nothing PPE persists or emits may tell a reader **who** handles **what** protected data, **where**
> it comes from, or **how much** — unless that reader holds both decryption parts.

What still leaves in clear is only what's needed to run and verify the system: liveness, latency,
error and drop counts, and the integrity chain of ciphertexts.

## Decision

### Record envelope (the only clear fields)

```
{ "v": 2, "seq": n, "prev": SHA-256(prev envelope),
  "kid_m": machine key id, "kid_u": token key id,
  "w_m": HPKE-wrap of share 1, "w_u": HPKE-wrap of share 2,
  "nonce": 96-bit, "ct": AES-256-GCM(DEK, record padded to a size bucket) }
```

- Everything else is inside `ct`: timestamp, event, caller, access principal, class, type, count,
  source, zone, action, model, detectors, lineage, value digests, policy hash. The clear header is
  the AEAD associated data, so it can't be swapped onto another ciphertext.
- Plaintext padded to fixed buckets (256 B / 1 KiB / 4 KiB) so record sizes don't fingerprint
  event types. One audit stream, constant file names, rotation by size (no per-caller, per-day or
  per-class files).
- The hash chain and signed C2SP checkpoints (ADR-0004) run over envelopes. Integrity is
  verifiable by anyone, contents by nobody without both parts.

### Two-part encryption (2-of-2)

Per record (or per batch flushed at most every second, to bound overhead):

1. Random 32-byte data key `DEK`; encrypt the padded record with AES-256-GCM.
2. Split the key: random `s1`, `s2 = DEK ⊕ s1` (a 2-of-2 XOR split; either share alone carries
   no information about `DEK`).
3. `w_m = HPKE.Seal(pk_machine, s1, info="ppe/audit/v2/machine", aad=header)`
   `w_u = HPKE.Seal(pk_token,   s2, info="ppe/audit/v2/token",   aad=header)`
   (RFC 9180 base mode, DHKEM(X25519, HKDF-SHA256) + AES-256-GCM; P-256 suite for a FIPS profile.)
   **Post-quantum (added 2026-10-02, case-study H11):** use a hybrid KEM — X-Wing (X25519 +
   ML-KEM-768, IETF draft) or the `draft-ietf-hpke-pq` hybrid — for both wraps from day one, with
   an `alg` field in the envelope for agility. The audit is long-lived, so harvest-now-decrypt-later
   applies. AES-256-GCM and the XOR split are already quantum-safe.

Writers (proxy, sensors, auditd) hold **public keys only**. Decryption needs both
`sk_machine` and `sk_token`. Shares can be unwrapped in different places and combined at the end,
so the token never has to be plugged into a machine that might be compromised.

| Part | Production | Development (now) |
|---|---|---|
| machine | X25519 key pair generated on the host; `sk_machine` sealed with `systemd-creds` + TPM2 and readable **only by the `ppe audit open` unit** — not by the proxy, sensors or auditd | same, or a `0600` file in the dev profile |
| token ("USB key") | private key on a hardware token (PIV / OpenPGP card / FIDO-backed), PIN-protected, held by the auditor; never on the host | **simulated**: `sk_token = X25519 key derived from Argon2id("1234", salt="ppe-dev-token-v1")`; the public key is installed on the host, the private key is derived only when the decrypter is given `"1234"` |

Dev-key safety rail: the dev token public key's fingerprint is a known constant. `standard` and
`hardened` profiles **refuse to start** with it, and every record written under it has
`kid_u = "dev-1234"` in the clear header, so dev records can never pass as production evidence.
`"1234"` appears only in dev fixtures and this ADR.

### The audit-grade decrypter

`ppe audit open --periods … --query …` runs as its own unit/account. It needs (1) access to
`sk_machine` (TPM-bound on the host, or an exported machine share prepared under ceremony) and (2) the
token (dev: prompts for `"1234"`). It:
- verifies chain and checkpoints before decrypting;
- produces the **exposure ledger**, coverage report, alert details, lineage, and investigations
  (value lookups use the sealed `k_dig`, as in ADR-0009);
- writes its own sealed record of every open (who, scope, reason), so opening the audit is itself
  audited under the same protection;
- outputs reports to a destination the operator chooses (encrypted at rest by default), never to the
  shared log stack.

### Real time without breadcrumbs (amends ADR-0004 / ADR-0007)

| Signal | Before | Now |
|---|---|---|
| Prometheus | findings/actions by class, type, zone, caller, detector | **health only**, no attribution labels: `ppe_up`, request/latency histograms, detector error and timeout counts, queue depth/drops, audit write failures, zone-verification failures (count only). Finding/action counters: **off by default** (dev profile may enable) |
| alerts | named rules with class/caller | rules evaluated **in process** on in-memory state; when one fires, PPE writes a sealed `alert` record with full detail and emits only `ppe_alerts_total{severity}` + a notice "PPE alert `<id>`, severity high — open with the audit decrypter". No rule name, class, caller or source |
| coverage gaps | "sensor X down" | sealed detail + opaque "coverage degraded" health signal (a sensor's name reveals a data source) |
| SIEM | metadata projection | sealed envelopes (for retention/integrity) + opaque alerts + health; the SOC escalates to the auditor to open details |
| exposure ledger | online report | offline, decrypter only |
| response headers `x-ppe-*` | counts and classes | **off by default** (dev/lab opt-in); production shows at most `x-ppe-ref: <opaque id>` |
| block / keep-local errors | named the class and message index | "Blocked by privacy policy. Reference `<opaque id>`." Class detail only in dev/lab |
| in-memory state (dedup, HLL, lineage, alert windows) | — | memory only; persisted only as sealed records; lost on restart (accepted) |

The opaque reference id is random per event (not a counter, not derived from the session), so ids
can't be correlated without decrypting.

### Retention and shredding (amends ADR-0003 / ADR-0009)

- Token key pairs rotate per period (monthly or quarterly — PLAN §6.15). Destroying a period's
  `sk_token` shreds every record of that period everywhere, backups and SIEM copies included.
  Destroying `sk_machine` (rotated on the same schedule) has the same effect independently.
- Dev: `"1234"` is deterministic and can't be shredded. Dev audits are disposable test data by
  definition (synthetic corpus only, per CONTRIBUTING).
- Loss of the token = loss of the audit. Production needs a **second escrowed token** (or a 2-of-3
  scheme across auditors) — design in a later ADR when the USB part is solved.

## Consequences

- Positive: a stolen audit, SIEM copy, metrics database or log stack tells an attacker nothing about
  who handles which data or how much. Even with the host fully compromised (machine key readable),
  the token part is missing. The observation plane keeps its value, but only for the auditor.
- Negative: no attribution dashboards. Operators see health and opaque alerts, and must open the
  audit to learn what happened (slower triage, by design). Alert tuning needs the decrypter. CSA's
  "logs streamed into a SIEM for SOC monitoring" is met only in envelope form; the deployer's
  assessment must explain why. More crypto per record (two HPKE wraps, ~0.1–0.3 ms each; batching
  amortises).
- Kent: Grafana PPE panels show health only; Kent notices for PPE alerts carry only the opaque id.

## Alternatives considered

- *HPKE PSK mode with `"1234"` as the PSK*: the PSK would be needed at **write** time, so the second
  factor would live on the host. Rejected.
- *Nested encryption (machine, then token)*: equivalent strength, but forces both decryptions to
  happen in order on one machine. The XOR split allows separate places. Rejected.
- *Clear occurrence records with restricted access* (ADR-0009): rejected by the operator — the
  breadcrumb argument.
</content>
</invoke>

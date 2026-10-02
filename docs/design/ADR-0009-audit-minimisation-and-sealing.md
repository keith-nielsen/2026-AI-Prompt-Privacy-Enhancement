# ADR-0009 — Audit minimisation: occurrence records in clear, value-derived fields sealed to an offline key

Status: **proposed** (2026-10-02). Operator direction (2026-10-02): an audit record of sensitive data
"becomes a high-value target for attackers in its own right"; privileged users and applications
with right-to-use credentials legitimately decrypt and work with protected data, and what must be
observed is **the occurrence** of protected data being worked with. Choice: *occurrences + sealed
digests*. **Amends ADR-0003 (keys, retention), ADR-0004 (record format, lookup), ADR-0007
(observation records, lineage, ledger).**

> **Superseded in part by [ADR-0010](ADR-0010-fully-sealed-audit.md) (2026-10-02):** the occurrence part is no longer in clear — whole records are sealed with two-part (machine + token) encryption. Value-digest sealing, the offline investigation procedure and key-destruction shredding carry over.

## Context

ADR-0004/0007 store `value_digest = HMAC(k_aud[p], type ‖ value)` in every record, and the proxy
holds the current `k_aud[p]` online. If an attacker gets the host (proxy memory or key file) and
the audit store, every digest of an enumerable class (NRIC/FIN ≈ 10⁷ candidates, phones ≈ 10⁸) can
be brute-forced in minutes. The audit then becomes a cleartext inventory of whose identifiers were
processed where. The observation plane multiplied that inventory to cover all processing. Rule:
**anything the online host can read, an attacker on the host can read.**

## Decision

### Split every record into two parts

| Part | Content | Readable by | Purpose |
|---|---|---|---|
| **Occurrence** (clear) | ts, seq, prev, event, action, zone, flow, class, type, **count**, source kind + coarse area/host, caller, **access principal** (see below), model, deployment, detectors + scores, policy_hash, key ids, `session_ref` (keyed, rotating), req_id | operator group, SIEM projection (subset) | real-time monitoring, exposure ledger, alerts, "who worked with how much protected data of which class, through which credential, where" |
| **Sealed** (HPKE ciphertext) | value_digest, token/surrogate digest, locator_digest, lineage links | **nobody online**; only the offline audit key | investigations: "did this NRIC go out / get processed, when, by whom" |

- Sealing: **HPKE** (RFC 9180, base mode; DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM —
  or the P-256 suite for a FIPS 140-3 profile) to the **period audit public key** `pk_aud[p]`.
  The record's occurrence part is the AEAD associated data, so a sealed blob can't be moved to
  another record.
- The online host holds **only public keys**. It can write sealed fields and can't read them —
  not old ones, not its own. The private keys `sk_aud[p]` are generated **offline** (air-gapped
  machine or HSM/smart card, two-person ceremony), and only `pk_aud[p]` is installed on the host.
- Inside the seal, digests are still keyed: `HMAC(k_dig, …)`. `k_dig` is a random key the **host
  generates in memory** at period start (and again after every restart, so one period may have
  several). It is written to the audit only **sealed to `pk_aud[p]`** (`event: digest_key`, with its
  key id) and never stored in clear. Investigators recover it offline. A host compromise
  therefore exposes digests only for values processed **while the attacker is present**, which the
  attacker could see in plaintext anyway. Nothing from the past.

### Access principal: "who worked with it, with which right"

The operator's premise is that privileged credentials legitimately decrypt protected data. The
occurrence record names the credential path, never the credential:

- `caller`: the identity at PPE (gateway key id, client token id, `SO_PEERCRED` uid).
- `access_principal` (data-source sensors, ADR-0007 S3): the tool/connector and the service identity
  it used to read the data (e.g. `tool=db_query, principal=svc-crm-readonly`, `tool=read_file,
  principal=uid:kent`). Tools and MCP servers report it in the sensor message; PPE records the id,
  never a secret.
- Result: "service account X fed 1,240 IDs of class NRIC into agent sessions this week, 96 % stayed
  on the local model, 4 % went to the cloud as surrogates, 0 in clear". All of it answerable from the
  clear part, without unsealing.

### What still works online (no private key)

| Need | How, without value-derived data in clear |
|---|---|
| dedup per identifier (agent loops) | in-memory set of `HMAC(k_dig, …)` for the current period; lost on restart (a few duplicate records, accepted) |
| **distinct counts** for the exposure ledger | per (class, zone, caller, source kind, day) HyperLogLog sketches over keyed digests, persisted as aggregate records. Registers of keyed hashes reveal nothing usable without `k_dig[p]`. Error ≈ 1–2 % (p = 14), stated on reports |
| lineage inside a live session | in-memory per session: first-seen source of each digest; written as occurrence fields (`first_seen: source:file/workspace`), not as links |
| alerts (bulk volume, new sensitive source, purpose mismatch, secrets in local flows) | counters and occurrence fields only |
| "did value V leave?" | **not online by design.** Offline procedure below |

### Investigation procedure (offline, four-eyes)

1. Request recorded (`event: lookup_requested`, requester, reason, ticket) on the host.
2. Export the relevant periods' audit files (they're append-only and signed, so integrity is checked
   on export: `ppe audit verify`).
3. On the offline workstation, two people unlock `sk_aud[p]` (HSM/smart-card PINs). Unseal
   `k_dig[p]`, compute the digest of the queried value, unseal and search the sealed fields.
4. Result and the fact of the lookup go back to the host's audit as `event: lookup_completed`
   (requester, approver, periods, result count — no value).
5. Rate and scope limits are procedural (ticket per subject, periods named), plus the HSM's own PIN
   and usage counters.

### Retention (amends ADR-0003)

- Crypto-shredding = **destroy `sk_aud[p]`** at period end + retention. All sealed fields of the
  period become permanently unreadable, wherever copies of the audit sit (backups, SIEM exports,
  stolen copies). That's stronger than deleting an online HMAC key, which backups may still hold.
- Occurrence parts stay for as long as the deployer's evidence policy says (they carry no
  value-derived data; they are still personal data about *callers* and keep restricted access).
- Online keys shrink to: `k_tok[e]` (tokens/surrogate seeds), current `k_dig` in memory only,
  `pk_aud[p]` (public), `k_sign` (checkpoint signing). Option-C escrow (ADR-0002), if enabled, is
  sealed the same way.

### What else on the host is a target, and its limit

| Item | Exposure | Limit |
|---|---|---|
| request vault (real ↔ surrogate) | plaintext in memory during the request | request lifetime; no dumps, no swap, no ptrace (ADR-0002) |
| `k_tok[e]` | lets an attacker who also holds provider-side data invert surrogates/tokens of enumerable classes by search | epoch rotation + deletion; not usable on the audit (seeds aren't recorded) |
| `k_dig` (current, in memory) | digests of values seen while the attacker is present | period length; never on disk in clear |
| occurrence records | who handled how much of which class | restricted group, no values |
| detector services | transient plaintext in memory | own accounts, no logging |

## Consequences

- Positive: a stolen audit store, even together with every key on the host, reveals no identifier,
  past or present. Monitoring, alerting and the exposure ledger run on clear occurrence data.
  Investigations stay possible, but only with a deliberate, two-person, recorded act. Shredding
  also reaches copies.
- Negative: no online lookup. "Was this NRIC sent?" takes an offline ceremony (by design). Distinct
  counts are approximate (HLL). Lineage across sessions is offline-only. Operators must run a small
  offline key ceremony per period (or per quarter with sub-keys) and keep HSM/smart-card custody.
- Stand-alone users without an offline machine: `lab`/`standard` profiles can keep `sk_aud` on a
  USB smart card (PIV/OpenPGP) or a passphrase-encrypted file stored off the host; documented as
  weaker.
</content>
</invoke>

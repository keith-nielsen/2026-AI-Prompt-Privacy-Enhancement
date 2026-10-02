# ADR-0003 — Retention by crypto-shredding; key hierarchy and custody

Status: **proposed** (2026-10-02). Resolves PLAN §7.2 and RESUME step 2. **Amended by ADR-0009**:
the online `k_aud[p]` is replaced by an offline HPKE key pair per period (`pk_aud[p]` on the host,
`sk_aud[p]` offline) plus an in-memory digest key. Shredding = destroying `sk_aud[p]`. Online lookups
are replaced by an offline two-person procedure. The `k_tok` epoch rules below are unchanged.
Sources: [pdpc-genai-guidelines.md](../sources/pdpc-genai-guidelines.md) (§7.2–7.3),
[pdpc-basic-anonymisation.md](../sources/pdpc-basic-anonymisation.md) (incident p.31–32),
[eu-edpb-enisa.md](../sources/eu-edpb-enisa.md), [nist.md](../sources/nist.md) (SP 800-57, SI-12),
[litellm-2026.md](../sources/litellm-2026.md).

## Context

The audit trail must be append-only and tamper-evident (CSA; NIST AU-9) **and** must stop being
linkable to individuals when its retention period ends (PDPA s.25: cease retention or "remove the
means by which personal data can be associated with particular individuals"). Rewriting a
hash-chained log to delete rows breaks its integrity. Deleting a key does not.

## Decision

### Keys — independent random keys, not derived from one root

Crypto-shredding only works if a deleted key cannot be re-derived. So period keys are **generated**
(32 bytes from `getrandom`), never derived from a long-lived master.

| Key | Purpose | Cryptoperiod (default) | Holder | Deleted |
|---|---|---|---|---|
| `k_tok[e]` | tokens + scope (ADR-0002) | epoch 30 days | PPE proxy | epoch end + 7 days grace |
| `k_aud[p]` | audit digests: `value_digest`, `token_digest`, `caller_digest` | period 1 month | audit writer; lookup CLI | period end + retention (default 12 months, deployer-set with written rationale) |
| `k_escrow[p]` | option C escrow (AES-256-GCM) | period 1 month | escrow service only | shortest workable (default 30 days) |
| `k_sign` | Ed25519 signing of audit checkpoints | 1 year, overlapping | audit writer only | never (public key archived for verification) |
| `k_client` | client bearer tokens to PPE | per client, rotatable | PPE + client | on revocation |

Each key has a `key_id` = first 8 bytes of SHA-256("ppe/kid/v1" ‖ key), recorded on every record.
SP 800-57 cryptoperiods; rotation is automatic (`ppe keys rotate` from a systemd timer).

### Custody tiers

| Tier | Storage | When |
|---|---|---|
| T0 | files `0600`, owned by the service account, on an encrypted volume | lab / stand-alone default |
| T1 | **systemd credentials**: `systemd-creds encrypt` with TPM2 + host key, `LoadCredentialEncrypted=`; plaintext only in the unit's private `$CREDENTIALS_DIRECTORY` tmpfs; `PrivateMounts=yes` | standard / Kent |
| T2 | TPM2-sealed or PKCS#11 HSM (non-exportable HMAC keys; HMAC computed inside) | hardened |

Separation of duties: only the proxy sees values, so it computes digests and holds `k_tok[e]` and
the **current** `k_aud[p]` only. Older `k_aud` keys live with the lookup tool (operator group), not
the proxy, so a compromised proxy cannot search past periods. The audit writer (separate account)
holds `k_sign` and the append-only file; the proxy cannot rewrite or sign. LiteLLM's account can read
none of these (the March 2026 LiteLLM PyPI payload stole exactly such files).

### Retention table (what exists, where, how long)

| Data | Where | Lifetime | Mechanism |
|---|---|---|---|
| plaintext, vault | PPE memory | request | destroyed at response end (ADR-0002 limits) |
| verdict cache | PPE memory | TTL 15 min | holds `(message_hash → findings: offsets, types, scores)`; message_hash = HMAC(k_tok[e], content); no values |
| audit records | local store | **forever on disk, linkable only while `k_aud[p]` exists** | crypto-shredding |
| escrow (option C) | local encrypted table | ≤ `k_escrow[p]` life | key deletion + file deletion |
| shadow-mode reports | local | 30 days | contain types/counts and redacted excerpts (`<TYPE>`), never values |
| tokens held by providers | provider | outside our control | unattackable after `k_tok[e]` deletion |
| metrics | Prometheus | backend policy | counters only, no values/tokens |

`ppe retention run` (systemd timer, daily): deletes expired keys and escrow, writes an audit record
for each deletion (`event: key_destroyed, key_id, period`), and verifies no expired key remains in
any custody tier. Destruction method: overwrite + unlink for T0 (best effort on SSD — hence the
encrypted volume), `systemd-creds` file deletion for T1, HSM object destroy for T2.

### What a lookup can answer, by age

| Question | While `k_aud[p]` exists | After shredding |
|---|---|---|
| "Did value V go to a cloud model? when, from whom, which model?" | yes (compute digest, search) | no |
| "Which conversation produced provider-held token T?" | yes (`token_digest`) | no |
| "What did token T stand for?" | only with option C escrow, while escrow lives | no |
| "Is the log intact? how many masks per class per day?" | yes | **yes** (chain + plaintext-free metadata survive) |

### Data-subject requests (PDPA Part IV, GDPR art. 15)

PPE can say *that* and *when* a person's identifier went to which provider, from which caller,
while the period key exists. It cannot produce content (none stored). The operator guide says so,
and points to the provider's retention terms for the content side.

### Incident playbook (PDPC Basic Anonymisation p.31–32 mapped)

| Lost | PDPC classification | Actions |
|---|---|---|
| provider-side data only (tokens) | de-identified data; masking "part of the protection mechanisms" | assess; rotate `k_tok` early (ends linkability of new traffic); no plaintext to report from PPE side |
| `k_tok[e]` only | "mapping table only" analogue | rotate immediately; tokens issued under `e` are now brute-forceable *by the key holder for enumerable classes, if they also get the tokens* → assess which providers hold epoch-`e` tokens |
| `k_tok[e]` **and** provider data | "akin to the breach of personal data" | treat as breach; PDPA s.26D assessment (notify PDPC within 3 calendar days of assessing notifiable) |
| audit store + `k_aud[p]` | pseudonymised personal data | breach assessment; shred affected periods if retention allows |
| escrow + `k_escrow[p]` | personal data in clear | breach |

## Consequences

- Positive: retention is enforced by deleting 32-byte keys, without touching the append-only log;
  integrity and aggregate reporting outlive linkability.
- Negative: an expired key cannot be recovered for a late investigation — the retention period must
  be chosen with legal input (deployer). Backups must not capture keys (or must be on the same
  rotation), or shredding is void: `ppe doctor` warns if the key directory is inside a backed-up path.
- Open: default retention 12 months is a proposal (PLAN §6.4); the deployer writes the rationale.
</content>
</invoke>

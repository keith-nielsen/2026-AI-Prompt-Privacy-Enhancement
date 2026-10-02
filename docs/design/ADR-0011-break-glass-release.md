# ADR-0011 — Break-glass release: two approvers unlock, one investigator uses, time-bound, auto re-arm

Status: **proposed** (2026-10-02). Operator direction (2026-10-02): a security operator must be able
to "decrypt on the fly using monitoring tools" for live review; that capability concentrates risk,
so: "two authorized individuals approve the key unlock (but they can never use the key themselves),
then that key goes to a specific user (who can never authorize the key unlock) for their
time-bounded investigation, which then auto closes after they are done and revokes the key and
re-arms the break-glass for the future." Builds on ADR-0010 (fully sealed, 2-of-2 audit).

## First principle: release a capability, never a key

A key that has been handed to a person can't be revoked. They can copy it, and anything they
decrypted they have seen. So in this design **nobody ever holds an audit private key**, not the
approvers, not the investigator, not root:

- private keys live **inside hardware** (TPM 2.0 on the broker host in our build; an HSM with an
  M-of-N quorum in larger deployments — the same idea as nShield operator-card sets or Luna M-of-N);
- the hardware performs the unwrap operations only while an **authorised policy session** is open;
- "the key goes to the investigator" means the investigator gets a **time-bound session on the
  decryption broker**, which decrypts on their behalf and shows them results;
- "revoke" means the hardware session ends and the broker forgets every derived secret. Nothing
  exists outside hardware that could still decrypt.

## Roles (disjoint, enforced in policy and in hardware)

| Role | Can | Can never |
|---|---|---|
| **Requester** (anyone on the security roster) | file a release request | approve their own request |
| **Approver** (≥ 3 enrolled, 2 needed) | sign approval of one exact request | be the investigator of a request; reach the broker's view API; hold key material |
| **Investigator** (enrolled) | use a granted session within its scope and time | approve any request; extend their own session; export without an export grant |
| **Custodian** (setup only) | run enrolment and key ceremonies with a quorum present | approve or investigate in the same quarter as a ceremony they ran |

Every person is identified by a key on their own hardware authenticator (FIDO2 / PIV). A person may
be enrolled in only one of {approver, investigator}. The broker refuses role overlap, and changing
the role roster itself needs a quorum signature (below).

## The release flow

```
1 REQUEST   requester → broker: {investigator, reason, ticket, scope, max_duration}
            broker returns request_hash + a fresh TPM nonce (one-shot, prevents replay)

2 APPROVE   approver A, approver B each sign (request_hash ‖ tpm_nonce ‖ period_key_ids ‖ expiry)
            with their hardware key; A ≠ B, neither = investigator, neither = requester

3 UNLOCK    broker opens a TPM policy session: TPM2_PolicySigned × 2 (approver keys fixed in the
            sealed objects' policy), PolicyOR over enrolled approver pairs, expiry from the
            signatures, PolicyNV one-shot counter → the TPM authorises use of exactly the period
            keys named in the approval, inside the TPM

4 GRANT     investigator authenticates to the broker with their own hardware key (+ PIN/biometric);
            gets a session credential bound to that key, short-lived (15 min, renewed silently
            while their authenticator is present), hard-capped at max_duration (default 4 h, max 12 h)

5 USE       broker decrypts on the fly and serves only what the scope allows (below); every query,
            view and export is written as a sealed audit record of the session

6 CLOSE     on investigator "done", expiry, authenticator removal, idle 15 min, or any approver's
            veto: TPM policy session flushed, in-memory DEKs and plaintext caches zeroed, session
            credential revoked, NV counter advanced

7 RE-ARM    broker writes a sealed close record + an access summary sealed to the approvers;
            notifies approvers and the investigator; new nonces; ready for the next request
```

Approvers approve by signing; at no step does any key material pass through their devices or
accounts. The investigator never touches a key either: they see decrypted views through the broker.

### Scope (least privilege, part of what approvers sign)

| Field | Values |
|---|---|
| `mode` | `live` (forward-only from grant time) · `historical` (named periods / time range) · both |
| `filters` | event types, classes, callers, sources, zones — the broker decrypts, filters internally, and shows only matching records |
| `export` | `none` (default: view only) · `report` (sealed report to a named destination) · `raw` (needs a separate approval) |
| `max_duration` | ≤ 12 h; extension = a new request with new approvals |

**Live mode needs no historical key.** At grant time the broker generates an ephemeral X25519 key
pair inside the TPM and publishes its public half to the writers. For the session's duration, writers
add a third wrap of each record's data key to it (still also 2-of-2 sealed for the permanent
record). At close, the ephemeral key is destroyed in the TPM; the extra wraps on records written
during the window become undecryptable. `live`-only requests therefore never unlock past periods.

### Monitoring tools

The broker exposes the decrypted view **only to the session holder**:
- `ppe audit tail` (TUI) and `ppe audit query`;
- a read-only, mTLS-protected datasource for the operator's monitoring tool (Grafana / Loki-style
  query API) bound to the session credential. It dies with the session; nothing is cached in the
  tool's own store (no panel snapshots, no alert rules persisted on decrypted data);
- every view is watermarked with the session id and investigator id (deterrent, traceability).

### Emergency path (option, default off)

If two approvers can't be reached, an investigator may request a **time-locked single-approver**
release: one approval + a mandatory delay (default 60 min). During the delay every enrolled approver
is notified and **any one can veto**. Scope is forced to `live` + `export: none`. Recorded as
`event: break_glass_emergency`.

## Roster and policy changes

- The approver set is baked into the sealed objects' TPM policy via `TPM2_PolicyAuthorize` with a
  roster key. Changing the roster (add/remove approver, change investigator list) needs a
  **quorum-signed** new policy. One approver can't add a friend.
- Approver/investigator removal takes effect immediately in the broker; TPM policy update follows
  the same quorum rule.
- Period keys rotate (ADR-0010). A historical release names period key ids; a stolen approval can't
  open other periods.

## What the broker host is, and its limits

The broker is a **separate, minimal service and account** (ideally a separate host or VM from the PPE
proxy). It has no network listener except the investigator API (mTLS) and the request/approval
endpoint, no shell access for investigators, and logs only sealed records. During an active session,
root on the broker host can read the plaintext the broker shows — the same exposure as the
investigator's screen. **Outside a session, root on the broker host can decrypt nothing** (no
approvals → TPM refuses).

## Development simulation (now)

| Production | Dev stand-in |
|---|---|
| TPM 2.0 policy sessions | `swtpm` (software TPM) **or** a pure-software policy engine with the same API, marked `dev` |
| approver hardware keys | two Ed25519 key files `approver-a`, `approver-b` (plus `approver-c` to test pairs) |
| investigator hardware key | Ed25519 key file `investigator-1` |
| token part (ADR-0010) | `"1234"` (Argon2id-derived X25519), used by the broker **only after** two valid approvals |
| machine part | file key (dev profile) |

Production profiles refuse dev keys (fingerprint check), as in ADR-0010.

## Hardening H1–H13 — **adopted by the operator 2026-10-02**

Source and evidence: [`../research/2026-10-02-break-glass-case-studies.md`](../research/2026-10-02-break-glass-case-studies.md) §7.
These are requirements of this ADR, not options.

| # | Requirement | Driven by |
|---|---|---|
| H1 | **Approve what you see, on your own device.** The canonical request (investigator, scope, periods, duration, reason) is rendered and signed on an approver-controlled device independent of the broker and requester (hardware key with display, or a dedicated approval app on a separate managed device). The broker's UI is never the only view. | Bybit, Bangladesh Bank |
| H2 | **Hardware signatures only**: FIDO2/PIV with user verification. Never push, SMS, voice, video or chat approvals. | Arup, Twitter, Uber |
| H3 | **Approver independence**: different reporting lines (ideally sites); no person or team controls a quorum; roles and delegations expire after 90 days unless re-confirmed by quorum. | Ronin, Barings, Coinbase |
| H4 | **Proof-of-possession sessions**: the investigator's session is bound to their hardware key on every request; no bearer tokens; diagnostics never contain session material. | Okta HAR files |
| H5 | **No static secrets** in the broker, its config or scripts; PPE's secret detector scans the broker config in CI. | Uber |
| H6 | **Velocity limits** (≤ 1 active release per investigator, weekly cap, cool-down after denial); auto-deny on anomaly; **no AI-agent identity may hold any role**. | GTG-1002, Replit |
| H7 | **Independent channel**: approvers' devices verify checkpoints and receive open/close notices without trusting the broker host. | Bangladesh Bank, Equifax |
| H8 | **Mandatory post-session review** by both approvers within N days; an unreviewed session blocks that investigator's next release. | UCLA |
| H9 | **Failure-domain separation**: ≥ 3 approvers; broker independent of the PPE host; offline decrypter (ADR-0010) as disaster path; second escrowed token stored separately. | CrowdStrike, Facebook, QuadrigaCX |
| H10 | **Quarterly break-glass drill** on synthetic data (request → approve → live view → close → verify); failure is a high-severity finding. | Facebook, CrowdStrike, PAL claim |
| H11 | **Hybrid post-quantum wraps** (X-Wing / ML-KEM-768 + X25519) for both shares, `alg` in the envelope; hybrid Ed25519 + ML-DSA checkpoints planned; prefer TPM 2.0 v1.85. | harvest-now-decrypt-later; NIST IR 8547; CNSA 2.0 |
| H12 | **Canary records**: synthetic sealed records with decoy G1/G2 surrogate values, watched for in egress and observation; any appearance = audit decrypted outside a release. | offline-compromise detection |
| H13 | **Monitor the monitors**: alarms on key/certificate expiry, TPM health, broker heartbeat, checkpoint gaps. | Equifax |

### Operational parameters are adopter-set (operator, 2026-10-02; see ADR-0012)

> Everything in this section is a **capability with example settings**. Deployers choose their own
> values, roles and procedures; [ADR-0012](ADR-0012-mechanism-not-policy.md) lists each knob with its
> trade-off and the test that proves it.

The operator rejected fixed numbers: review time depends on incident count and batching; release
volume "totally depends on incident volume" and can be very bursty during an active security
event, and limits "must not become a valid denial source"; drill ownership depends on the people
available and the corporate structure. External audit is ideal but not realistic for every
organisation. So H6, H8 and H10 become **policy with safe defaults**, and the design must never let
a limit block legitimate incident response.

**H6 — velocity limits that can't be turned into denial of service**

- **Incident mode.** A quorum (the same 2 approvers) can declare an *incident envelope*: incident id,
  reason, a named set of investigators, scope ceiling (modes, periods, filters, export), and a
  window (default 24 h, renewable by quorum). Inside the envelope, investigators open and renew
  sessions **without new approvals per session**, up to the envelope's ceiling; the per-investigator
  and weekly caps don't apply; every session is still sealed-logged and reviewed (H8).
- **Normal mode.** Volume limits are **alerts, not denials**: exceeding a baseline raises an opaque
  alert to approvers. The only hard denials are: (a) **machine-speed ceilings** (e.g. requests per
  minute far above any human rate — the AI-speed attack signature), (b) role/policy violations,
  (c) an approver veto.
- **Limits are per identity, never global.** One requester (or an attacker flooding requests)
  consumes only their own budget; unenrolled or unauthenticated callers consume nothing;
  denied/expired requests count against the requester only. So no one can exhaust capacity
  others need.
- **Approver-fatigue protection** (the MFA-bombing pattern): identical or overlapping pending
  requests are merged into one approval prompt; a requester's flood is collapsed and flagged, not
  forwarded as many prompts.

**H8 — post-session review sized to load, batchable**

- Review deadline is a policy value per session class:

| Session class | Review | Default deadline |
|---|---|---|
| live-only, view-only, inside an incident envelope | **batch** (one signed review covers many sessions) | envelope close + policy days |
| live-only, view-only, normal mode | batch | policy days (deployer sets; e.g. weekly batch) |
| historical, any export, emergency path | **individual** | shorter policy deadline |

- Batch review = approvers sign one summary covering a set of session ids (counts, scopes, anomalies
  highlighted; details openable through the decrypter).
- Overdue review **never blocks during a declared incident**. It accrues as "review debt" (opaque
  alert). Outside incidents, debt older than the deadline blocks *new normal-mode* releases for that
  investigator only, never incident-envelope sessions.

**H10 — drill ownership (examples of how adopters may assign it)**

| Example | Drill owner | Evidence |
|---|---|---|
| A (ideal) | external auditor / assessor | signed drill report |
| B | internal audit or second-line risk function | signed drill report |
| C (small org) | a rotating approver who did not design the drill + the deployer's accountable executive | signed drill report |

The minimum rule in every tier: the drill owner is never an investigator in that drill. Drill runs
are sealed and checkpointed, so an external reviewer engaged *later* can verify past drills after
the fact, even if they weren't present.

**Fewer than 3 eligible people**: the mechanism offers `release_mode: 1 approver + time-lock` with
notification to a contact the adopter names, live-only, no export; `ppe explain` reports it as a
weaker setting and states what is given up.

## Consequences

- Positive: live, on-the-fly decryption for a security operator becomes possible without anyone
  ever holding a key. Three distinct people are needed (two approvers + investigator), every use is
  scoped, time-bound, recorded and auto-closed. Re-arming is automatic.
- Negative: a broker service + TPM policy engineering (the hardest code in the project). Approver
  availability becomes an operational dependency (mitigated by ≥ 3 approvers and the optional
  emergency path). TPM ECDH operations are slow (~tens of ms), so live view works (records are
  batched per second) and bulk historical queries are slow.
- Residual: collusion of two approvers and one investigator; root on the broker host during an
  active session; whatever the investigator memorises or photographs (watermarks deter).

## Alternatives considered

- *Shamir shares of the key held by approvers*: the key is reconstructed somewhere, and approvers
  handle key material. Violates "can never use the key themselves". Rejected (fine as an offline
  disaster-recovery escrow).
- *Give the investigator a short-lived decryption key*: can't be revoked. Rejected.
- *Always-on decrypted SOC view*: concentrates the vulnerability permanently. Rejected (ADR-0010).
</content>
</invoke>

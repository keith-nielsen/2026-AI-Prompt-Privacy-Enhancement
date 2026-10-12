# ADR-0013 — Restricted zone: identity walls, sticky session labels, canaries, outward-action checks

Status: **proposed** (2026-10-05, draft for operator review). Builds on ADR-0001 (zones), ADR-0006
(egress guard), ADR-0007 (observation plane), ADR-0010 (sealed audit), ADR-0012 (mechanism, not
policy). Kent facts below were read from `harness-kent` at `147ea99` (read-only; nothing run).

## Context

Operator, 2026-10-05: *"If the user or root wants to actively circumvent there is not much we can do.
I'm trying to catch the Kent/Gent automation that makes a poor decision and extracts/copies data it
should leave in restricted areas."*

So the adversary is **our own automation** — a mistaken decision, or one steered by a prompt
injection in something it read — not the machine owner. Unlike a person, automation runs under
identities we control, and every way it moves data passes a system call, a tool call or the gateway.
That can be enforced, not just hoped for.

Measured constraints from 2026-10-03/04 (`bench/2026-10-03-*.md`): span models cost 0.5–1.5 s per KB
on this CPU; Kent's model reads ~460 tok/s but cannot reliably enumerate identifiers in large files
(recall 0.57–1.0; whole categories dropped). Content inspection of large inputs at request time is
therefore expensive and incomplete. **Where data may flow must be decided by where it came from
(labels), not only by what it looks like (detectors).**

### How automation can move restricted data (generic)

| # | Path | Example |
|---|---|---|
| P1 | read it, put it in a cloud prompt | agent reads a customer CSV, asks the cloud model about it |
| P2 | copy it out of the restricted area | `cp`, `cat >`, a script, `/tmp`, a shared folder, a git repo; something sends it later |
| P3 | send it through another channel | `git push`, HTTP upload, messaging/e-mail/MCP tool |
| P4 | launder it through another agent | an agent allowed to read it returns a summary to one that can reach the cloud; derived text defeats exact matching |

### Kent today (read from the repo)

| Fact | Where | Relevance |
|---|---|---|
| Kent's Hermes runs in `bwrap`: own namespaces, caps dropped; operator folders absent unless granted per session (`kent --grant DIR` read-only, `--grant-rw DIR`); grants audited | architecture §12.4 | the grant **is** the moment restricted data enters automation — a natural place to set a label |
| For read-write grants "the approval gate … is still the only check (staged writes are the planned fix)" | §12.4 | P2 into granted folders is unchecked today |
| Kent calls router/fast/smart/frontier/auto with one `kent` key; tier policy is per key in `kent_gateway.py` (Gents: local only) | §1.2, §3 | the gateway already enforces "this identity may only use local tiers" — reusable for labels |
| Gents receive only `project.yaml`, `agents.yaml`, `tasks.yaml` (size-capped) via `kent new` / Kent's design; no operator data files | `kent` `pack_project`, §7 | restricted data reaches a Gent only through text Kent writes into its specs (P4) |
| Escalation: a Gent writes `escalation_request` → `kent-poll-learnings` asks **frontier** with Kent's key | §1.3, `kent_poll_learnings.py` | P4: Gent text to cloud |
| Assessment sends selected workspace content to frontier | `kent_gent.py` | P4 |
| Nightly QA sends Gent outputs to frontier | `kent_qa_audit.py` | P4 |
| All of Kent's automated cloud calls go through one function, `kentlib.gateway_chat` | `kentlib.py` | single choke point for a label check |
| Gent egress goes through Squid | `configs/kent-squid.conf` | a P3 channel to check per label |
| Hardened profile denies `curl`/`wget`/`python -c`/`nc` in Kent's shell; lab does not | §14.1 | command denylists are bypassable (P3) |
| Hermes hooks in use: `pre_llm_call` (notices) only | `configs/hermes/base.yaml` | `pre_tool_call` / `post_tool_call` are available attachment points (ADR-0007) |

## Decision

Two zones and one-way walls ("no read up, no write down"), enforced in this order of strength:
kernel/credentials → gateway → tool hooks → content checks → detection and alerts.

### 1. Restricted zone and labels (mechanism)

- A **restricted zone** is a set of directories the adopter declares (`restricted.paths`). Content
  read from it, and everything derived from it, carries the label `restricted`.
- Labels attach to **sessions** (an agent run, a Hermes session, a Gent), to **files** (extended
  attribute `user.ppe.label` plus a signed inventory entry), and to **content** (keyed fingerprints).
- **Sticky:** once a session reads restricted content it stays restricted until it ends. Coarse on
  purpose: it does not track individual values, so paraphrase cannot launder through it (P4). This is
  information-flow control at session granularity (prior art to check before reuse: Google DeepMind
  CaMeL and Microsoft FIDES, 2025).
- **Ratchet:** anything may raise a label; lowering one needs the signed scanner verdict or an
  operator approval (`restricted.declassify_approvers`: 1 or 2 — adopter knob). Every label change
  is sealed-audited (ADR-0010).

### 2. What a restricted session may do (invariants)

| Action | Unlabelled session | Restricted session |
|---|---|---|
| cloud tiers (smart/frontier/auto→cloud) | allowed (PPE egress guard applies) | **refused**; local tiers only |
| read restricted paths | **denied by the kernel** | allowed |
| write | working area | **only** the restricted zone or its own scratch; files it writes inherit the label |
| network | per profile | **no direct network**; only the local gateway (and local model) |
| hand work to another agent (spawn, task spec, reply) | allowed | the receiver inherits the label |
| outward tools (git push, HTTP, messaging, MCP) | checked (§4) | **refused** unless the target is inside the zone |

### 3. Enforcement points

1. **Identity/credential wall (strongest).** The launcher that opens a restricted grant starts the
   session with a **different gateway credential** (`<identity>-restricted`) whose gateway policy
   allows local tiers only — the same mechanism that keeps Gents local today. No header to forge:
   the label is the key the process holds.
2. **Network wall.** A restricted session runs in its own network namespace whose only route is a
   socket to the local gateway (as Gents reach it through their bridge). This closes P3 regardless of
   shell denylists.
3. **Filesystem wall.** Restricted paths are readable only by restricted sessions (group + mode, or
   by being mounted only into them); a restricted session's writable mounts are the zone and its
   scratch (Landlock or bind mounts; Kent: bwrap). Closes P2 for anything that must use file access.
4. **Label inheritance at hand-offs.** Spawning, task specs, escalations and replies carry the
   sender's label (recorded by the trusted component that performs the hand-off, not by the agent).
   Any cloud call on behalf of labelled work is refused or kept local (P4).
5. **Outward-action check at the tool layer.** A `pre_tool_call` hook (Hermes; Claude Code
   PreToolUse) inspects outward actions — git push, HTTP calls, messaging/MCP sends, file writes
   outside the zone — against session label, file labels, fingerprints and canaries before they run.
   It sees plaintext that a TLS proxy cannot.
6. **Egress guard (ADR-0006) as backstop** for whatever reaches the gateway: label check, fingerprint
   match, canary match, then the detectors (ADR-0005).

### 4. Content checks that need no model

- **Fingerprints:** keyed hashes (HMAC under a PPE key) of content-defined chunks of every file in the
  zone, so copies and large excerpts match exactly wherever the scanner or egress guard looks
  (working area, outbound payloads). Short fragments and paraphrase fall back to labels and detectors.
- **Canaries:** a few unique synthetic records planted in the zone (fake person, NRIC-shaped value,
  key-shaped string), generated per install, kept only as keyed digests. A canary outside the zone —
  egress payload, working area, git history, logs, an agent's output — is a high-confidence alarm that
  automation moved restricted data. They also exercise the whole pipeline continuously.
- **Inventory:** the signed, append-only, hash-chained list of labels per content hash (scanner runs
  under its own account and signs with Ed25519; PPE holds the public key only, so the runtime cannot
  forge a downgrade). Entries are keyed by HMAC of content, not by path, so the inventory is not a
  map of where sensitive files are (ADR-0010); a path index for operators is sealed.

### 5. Detection and alerts

Sealed audit (ADR-0010) for: restricted reads by agents, label changes, denied writes/sends/tier
calls, canary and fingerprint hits. Alert (opaque reference only) on: canary hit anywhere; a
restricted session attempting an outward action or cloud tier; fingerprint hit outside the zone.

### 6. Proof: conformance suite (`ppe verify --restricted`)

A deliberately badly-behaved test agent, run per install with synthetic data only:

1. unlabelled identity reads a restricted path → kernel denies;
2. restricted session `cp`s a zone file to the working area → denied;
3. restricted session `curl`s / opens a socket out → no route;
4. restricted session calls a cloud tier → gateway refuses;
5. a Gent spawned or tasked from a restricted session escalates → kept local / refused;
6. assessment of labelled work → refused for cloud;
7. a canary placed in an outbound payload → blocked + alert;
8. an unlabelled session lowers a label → refused without the scanner signature or approvals.

Every check must deny, block or alert; the report is the evidence that the walls exist on that host.

### 7. Where it lives (PLAN §4: nothing Kent-specific in the core)

| PPE core (generic) | Kent integration (Kent's installer) |
|---|---|
| label model, inventory signing/verification, fingerprints, canaries, egress label/canary checks, tool-hook library, `ppe verify --restricted`, Landlock launcher for stand-alone use (`ppe run --restricted DIR -- <agent>`) | `kent --grant-restricted DIR` (or a restricted flag on existing grants) in `kent`/`kent-exec`; `kent-restricted` gateway key and policy in `kent_gateway.py`; bwrap network namespace for restricted sessions; label column in `stack_registry`, set by the root brokers; label check in `kentlib.gateway_chat`, `kent-poll-learnings`, `assess`, `qa-audit`; Hermes `pre_tool_call` hook; restricted Gents without the egress proxy |

### 8. Knobs (ADR-0012)

| Knob | Options | Example default | Trade-off |
|---|---|---|---|
| `restricted.paths` | directories | none (adopter declares) | coverage vs friction |
| `restricted.session_tiers` | local only / block all inference | local only | usefulness vs exposure |
| `restricted.declassify_approvers` | scanner only / 1 / 2 | 2 in hardened, 1 otherwise | speed vs insider/automation risk |
| `restricted.outward_tools` | refuse / approve each | refuse | automation vs control |
| `restricted.canaries` | count, types | 3 per zone | detection vs clutter |
| `restricted.fingerprint_chunk` | average chunk size | 4 KB | excerpt sensitivity vs index size |

## Consequences

- Positive: P1–P4 are blocked by identity, credential and network walls for the automation we care
  about, without depending on detectors that measured slow and incomplete on large inputs; derived
  text (summaries) is covered by labels; canaries give near-zero-false-positive detection; the suite
  proves it per install.
- Negative: coarse labels taint whole sessions — tasks touching restricted data must be scoped to
  their own sessions/Gents, and those run on local tiers only (weaker answers). More moving parts in
  Kent's launcher, gateway policy and brokers. Restricted sessions lose web access.
- Not covered: the machine owner or root circumventing on purpose (out of scope by decision);
  restricted data the operator types or pastes into a prompt (inline detectors only); paraphrase by an
  *unlabelled* session of data it should never have seen (prevented by the filesystem wall, not
  detected).

## Findings for Kent (outside this package; for the operator)

Findings from the read-only review of `harness-kent` are tracked privately with Kent; not repeated in the public PPE docs.

## Alternatives considered

- *Content detection only* (ADR-0005 on everything) — measured too slow and incomplete for large
  inputs; cannot see derived text.
- *Per-value taint tracking* — precise but infeasible across LLM calls (models transform text);
  session granularity is the practical unit.
- *Path-based inventory only* — breaks on copies, renames and fragments; content keys plus labels
  cover them.
- *Trust agents to follow instructions about restricted folders* — the failure mode this ADR exists
  to catch.

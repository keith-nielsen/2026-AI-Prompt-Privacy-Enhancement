# ADR-0001 — Trust zones: loopback is the only local zone

Status: **proposed** (2026-10-02). Operator decision taken: "local" = loopback only.
Sources: [nist.md](../sources/nist.md) (AC-4, SC-7), [claude-code-gateway.md](../sources/claude-code-gateway.md),
[litellm-2026.md](../sources/litellm-2026.md), [prior-art.md](../sources/prior-art.md).

## Context

PPE decides per request whether text may leave in clear. The decision rests on one fact: *does the
selected endpoint process the text on this host, with nothing forwarded off it?* Getting this wrong
silently defeats every other control. An operator tag alone is a claim, not evidence; an IP address
alone is not enough either (see "Loopback is not local" below).

## Decision

### Two zones

| Zone | Meaning | Default treatment |
|---|---|---|
| `loopback` | an inference endpoint on **this host**, verified as below | untouched (no masking); allowed for every class including `special` (keep-local target) |
| `cloud` | everything else: provider APIs, **LAN and VPN hosts**, other containers' bridge IPs, anything unverified or untagged | policy per class: block / swap / pass |

There is no "private network" tier. A GPU box on the LAN is `cloud` for PPE's purposes (operator
decision 2026-10-02; consistent with treating the host as the boundary).

### What counts as loopback (all must hold, checked at config load **and** per request)

1. **Address**: a UNIX domain socket path, or an IP literal in `127.0.0.0/8`, `::1`, or IPv4-mapped
   `::ffff:127.0.0.0/104`. The hostname `localhost` is accepted only by mapping it to `127.0.0.1`
   inside PPE, never via the resolver (`/etc/hosts` and NSS can be changed; the IETF
   "let localhost be localhost" draft never became an RFC). Any other hostname → `cloud`.
2. **No intermediary**: the HTTP client used for loopback traffic ignores proxy environment variables
   (`trust_env=False` in httpx terms). Kent sets proxy variables for Squid; a loopback request must
   not be routed through a proxy.
3. **Terminal endpoint attestation**: the operator tags the deployment `privacy_zone: loopback` and
   names its kind (`kind: llama-server | ollama | vllm | …`). PPE refuses the tag when the
   address is its own listener, a known gateway (LiteLLM's port, another PPE, PasteGuard/Kiji
   defaults), or answers like a gateway (e.g. `/v1/models` lists provider-prefixed cloud models).
   *Loopback is not local*: `127.0.0.1:4000` on Kent is LiteLLM, which forwards to Anthropic.
4. **Peer verification** (assurance levels; profile picks the minimum):

| Level | Check | Available |
|---|---|---|
| L1 | address + no intermediary + attestation (1–3) | always |
| L2 | **peer process identity**: UNIX socket `SO_PEERCRED` (uid, pid) → `/proc/<pid>/exe` matches an allowlisted binary path/hash; for TCP loopback, map the socket inode via `/proc/net/tcp*` to the listening pid (same-uid or privileged only) | Linux |
| L3 | **peer cannot egress**: the peer's systemd unit has `IPAddressDeny=any` (+ `IPAddressAllow=localhost`) or runs in a network namespace without a default route; checked via `systemctl show` / `/proc/<pid>/ns/net` | Linux + systemd |

Profiles: `lab` ≥ L1, `standard` ≥ L2, `hardened` = L3. An endpoint that falls below the profile's
level is treated as `cloud`, never as "local but warned".

5. **Untagged → `cloud`** (PLAN §6.1, now decided by this ADR's fail-safe rule).

### PPE's own inbound side (it holds plaintext; it is the honeypot)

- Listen on a UNIX socket (`0660`, group `ppe-clients`) by default; TCP only on `127.0.0.1`/`::1`.
  Refuse to start on `0.0.0.0`/`::` or any non-loopback address. Container docs use
  `-p 127.0.0.1:PORT:PORT` (the common `-p 3000:3000` publishes on every interface).
- Client authentication even on loopback (other local users and processes can connect): bearer token
  from a `0600` file / systemd credential; constant-time compare.
- **DNS-rebinding and browser defence** (Ollama CVE-2024-28224 class): accept only `Host` values
  `localhost`, `127.0.0.1`, `[::1]` (+ port) or the socket; reject any request carrying an `Origin`
  header not on an explicit allowlist (browsers send it; CLIs and SDKs do not); no CORS headers.

### Non-bypassability of the cloud leg (reference-monitor property "always invoked")

PPE can only protect traffic that passes through it. Required deployment controls (documented,
checked by `ppe doctor`, not enforced by PPE itself):

- Host egress: provider domains reachable only by PPE's service account (Kent: Squid ACL by source
  user / port; stand-alone: nftables `meta skuid` rule or systemd `IPAddressDeny=` on client units).
- Claude Code: managed `allowedProviders: ["customEndpoint"]` with the pinned `ANTHROPIC_BASE_URL`.
- LiteLLM: cloud deployments' `api_base` points at PPE's egress listener (ADR-0006), and LiteLLM's
  account cannot reach provider domains directly.

### Amendment (ADR-0007, 2026-10-02)

With the observation plane, PPE is the only client of every loopback model server: LiteLLM's
loopback deployments point at PPE's observe listener, and the model server listens on a UNIX socket
in a group only PPE belongs to. The checks above then run on the PPE → model hop, where PPE can use
`SO_PEERCRED` itself (L2 without `/proc/net` lookups), and any other process reaching the model is a
permission error, i.e. a coverage alert, not a silent bypass.

## Consequences

- Positive: "local" becomes a verified property of a process, not a label. LAN inference servers
  are simply cloud (they still get masking), which removes a whole class of misconfiguration.
- Negative: a LAN GPU box cannot be a keep-local target. Operators who need that must tunnel it to a
  loopback socket on this host (e.g. SSH `-L` to a UNIX socket) — which makes the tunnel endpoint L1
  at best (the peer process is `ssh`, not the server), so `standard`/`hardened` still treat it as
  cloud. This is deliberate; revisit only by a new ADR.
- L2/L3 checks are Linux-specific; macOS/Windows stand-alone users get L1 and a warning.
- Requires tests: hostname tricks (`127.0.0.1.nip.io`, `localhost.` with trailing dot, decimal/octal
  IP forms `2130706433`, `0177.0.0.1`), proxy-env leakage, socket peer spoofing, PPE-to-PPE loops.

## Alternatives considered

- *Operator tag only* — rejected: one typo sends regulated text to a cloud tier unmasked.
- *Three tiers incl. attested LAN* — operator chose loopback only; LAN requires TLS + remote
  attestation PPE cannot verify.
- *Treat everything as cloud (always mask)* — safe but kills keep-local and wastes latency on local
  traffic; available as the `paranoid` policy for users with no local model.
</content>
</invoke>

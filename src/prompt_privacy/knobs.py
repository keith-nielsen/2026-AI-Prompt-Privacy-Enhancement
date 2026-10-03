"""The knob catalogue (ADR-0012): every setting with its trade-off and the test that proves it.

Single source for `ppe explain`. `implemented=False` knobs are part of the design but not built yet;
explain says so rather than pretending.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Knob:
    path: str  # dotted path in the policy file
    options: tuple[str, ...]
    default: str
    gain: dict[str, str]  # option -> what you gain
    give_up: dict[str, str]  # option -> what you give up
    test: str
    adr: str
    implemented: bool = True
    lab_only: tuple[str, ...] = ()


KNOBS: tuple[Knob, ...] = (
    Knob(
        "detection.phone_context",
        ("optional", "required"),
        "optional",
        {
            "optional": "every phone-shaped number in SG/NANP/UK form is protected (bench recall 1.000)",
            "required": "no false positives on order/reference numbers (bench precision 1.000)",
        },
        {
            "optional": "some order/reference numbers are swapped too (bench precision ~0.92)",
            "required": "numbers with no nearby context word leak, e.g. CSV phone columns (recall ~0.85)",
        },
        "ppe bench --phone-context optional|required",
        "ADR-0005",
    ),
    Knob(
        "swap.form",
        ("surrogate", "token"),
        "surrogate",
        {
            "surrogate": "models see realistic data and behave naturally",
            "token": "unmistakably artificial placeholders; simplest restore",
        },
        {
            "surrogate": "pool-generated names/addresses (G4) may match real people; more complex restore",
            "token": "models may handle placeholders less naturally",
        },
        "tests/unit/test_engine.py (R1-R3), tests/unit/test_surrogates.py",
        "ADR-0002, ADR-0008",
    ),
    Knob(
        "audit.second_part",
        ("dev_passphrase", "passphrase", "usb_token", "hsm"),
        "passphrase",
        {
            "dev_passphrase": 'zero setup for development (fixed string "1234")',
            "passphrase": "second key part never stored on the host",
            "usb_token": "hardware-held second part",
            "hsm": "non-exportable, quorum-capable",
        },
        {
            "dev_passphrase": 'no protection at all: anyone knows "1234"; refused outside lab',
            "passphrase": "weak passphrases are guessable offline",
            "usb_token": "token loss = audit loss without escrow",
            "hsm": "cost and operations",
        },
        "ppe verify (one-part-decrypt-fails, dev-key-refused)",
        "ADR-0010",
        lab_only=("dev_passphrase",),
    ),
    Knob(
        "audit.pq_wraps",
        ("hybrid",),
        "hybrid",
        {"hybrid": "ML-KEM-768 + X25519: resists harvest-now-decrypt-later"},
        {"hybrid": "~1.2 KB per wrap per record"},
        "tests/audit/test_envelope.py",
        "ADR-0010 (H11)",
    ),
    Knob(
        "on_error",
        ("keep_local", "block", "pass_and_log"),
        "keep_local",
        {
            "keep_local": "no silent leak when a detector fails",
            "block": "no silent leak; simplest",
            "pass_and_log": "availability during experiments",
        },
        {
            "keep_local": "needs a loopback model",
            "block": "cloud unavailable during detector outages",
            "pass_and_log": "protected data may leave in clear; lab only",
        },
        "fault-injection tests (Phase 2 proxy)",
        "ADR-0005",
        implemented=False,
        lab_only=("pass_and_log",),
    ),
    Knob(
        "zones.local_assurance",
        ("L1", "L2", "L3"),
        "L2",
        {"L1": "portable", "L2": "peer process verified", "L3": "peer proven unable to egress"},
        {"L1": "weakest proof that 'local' is local", "L2": "Linux only", "L3": "Linux + systemd setup"},
        "zone-spoofing suite (Phase 2)",
        "ADR-0001",
        implemented=False,
    ),
    Knob(
        "observe.mode",
        ("off", "model_legs", "model_legs+sources"),
        "model_legs",
        {
            "off": "least load",
            "model_legs": "see sensitive data on every model call",
            "model_legs+sources": "see where sensitive data enters (tools, files)",
        },
        {
            "off": "no idea what you are protecting",
            "model_legs": "data sources invisible",
            "model_legs+sources": "more sensors, more (sealed) records",
        },
        "coverage test (Phase 2)",
        "ADR-0007",
        implemented=False,
    ),
    Knob(
        "breakglass.release_mode",
        ("off", "single_timelock", "k_of_n"),
        "off",
        {
            "off": "nothing to attack online",
            "single_timelock": "live review in small teams",
            "k_of_n": "live review with two-person integrity",
        },
        {
            "off": "investigations only via the offline decrypter",
            "single_timelock": "one person + delay",
            "k_of_n": "a broker service whose sessions concentrate risk",
        },
        "break-glass suite H1-H13 (later phase)",
        "ADR-0011",
        implemented=False,
    ),
)

INVARIANTS: tuple[str, ...] = (
    "PPE never persists or emits plaintext protected values (audit, metrics, logs, errors, headers).",
    "Untagged or unverifiable endpoints are cloud.",
    "Secrets are never live-validated against their issuer.",
    "Restore is closed-world (only values issued in this request's vault).",
    "In break-glass no person is ever handed a decryption key.",
    'Dev keys (the "1234" token stand-in) are refused outside the lab profile.',
    "The audit integrity chain is always on.",
    "Relaxed safety settings exist only in lab, and records written under them carry the profile.",
)


def get(policy: dict[str, Any], path: str) -> Any:
    node: Any = policy
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def explain(policy: dict[str, Any]) -> str:
    profile = policy.get("profile", "personal")
    lines = [f"Profile: {profile}", "", "Invariants (not configurable):"]
    lines += [f"  - {i}" for i in INVARIANTS]
    lines.append("")
    for k in KNOBS:
        value = get(policy, k.path) or k.default
        state = "" if k.implemented else "  [designed, not built yet]"
        lines.append(f"{k.path} = {value}{state}   ({k.adr})")
        lines.append(f"    protects: {k.gain.get(value, '?')}")
        lines.append(f"    gives up: {k.give_up.get(value, '?')}")
        others = [o for o in k.options if o != value]
        if others:
            lines.append(f"    alternatives: {', '.join(others)}")
        if value in k.lab_only and profile != "lab":
            lines.append("    !! NOT ALLOWED outside the lab profile")
        lines.append(f"    proven by: {k.test}")
    return "\n".join(lines)

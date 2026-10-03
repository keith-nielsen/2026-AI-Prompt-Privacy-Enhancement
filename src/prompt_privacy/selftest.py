"""`ppe verify`: conformance self-tests on synthetic data (ADR-0012 §5).

Each check proves one claim the design makes. Phase 1 covers the engine, surrogates and the sealed
audit; proxy, zone and break-glass checks join as those phases land.
"""

from __future__ import annotations

import json
import tempfile
from collections.abc import Callable
from pathlib import Path

import jsonschema

from prompt_privacy import bench, policy
from prompt_privacy.audit.envelope import BUCKETS, open_envelope
from prompt_privacy.audit.keys import AuditKeyPair, dev_token_keypair
from prompt_privacy.audit.log import AuditLog, DevKeyRefused, open_log, verify_chain
from prompt_privacy.core.checksums import iban_valid, luhn_valid, nric_valid
from prompt_privacy.core.engine import Engine, Message
from prompt_privacy.core.keys import TokenKey
from prompt_privacy.core.types import EntityType
from prompt_privacy.corpus.generator import Generator

Check = tuple[str, bool, str]


def _audit_fixture(tmp: Path) -> tuple[Path, AuditKeyPair, AuditKeyPair]:
    m, u = AuditKeyPair.generate(), dev_token_keypair()
    log = AuditLog(tmp / "a.jsonl", m.public, u.public, "lab")
    for i in range(5):
        log.append({"event": "mask", "type": "NRIC", "caller": f"svc-crm-{i}", "count": i})
    return tmp / "a.jsonl", m, u


def check_dev_key_refused() -> Check:
    with tempfile.TemporaryDirectory() as d:
        try:
            AuditLog(Path(d) / "x.jsonl", AuditKeyPair.generate().public, dev_token_keypair().public, "team")
        except DevKeyRefused:
            return 'dev token ("1234") refused outside lab', True, ""
    return 'dev token ("1234") refused outside lab', False, "AuditLog accepted the dev key in profile team"


def check_one_part_fails() -> Check:
    name = "audit opens only with BOTH parts"
    with tempfile.TemporaryDirectory() as d:
        path, m, u = _audit_fixture(Path(d))
        env = json.loads(path.read_text().splitlines()[0])
        wrong = AuditKeyPair.generate()
        for label, a, b in (("machine only", m, wrong), ("token only", wrong, u), ("swapped", u, m)):
            try:
                open_envelope(env, a, b)
                return name, False, f"{label} decrypted a record"
            except Exception:  # noqa: S112 — any failure is the expected outcome
                continue
        return name, open_envelope(env, m, u)["caller"] == "svc-crm-0", ""


def check_no_breadcrumbs() -> Check:
    name = "envelope exposes no record fields (no breadcrumbs)"
    with tempfile.TemporaryDirectory() as d:
        path, _, _ = _audit_fixture(Path(d))
        raw = path.read_text()
        leaked = [w for w in ("svc-crm", "NRIC", "mask", "caller") if w in raw]
        env = json.loads(raw.splitlines()[0])
        jsonschema.validate(env, policy.schema("audit-envelope"))
        return name, not leaked, f"found {leaked} in clear" if leaked else ""


def check_tamper_detected() -> Check:
    name = "tampering detected (ciphertext, header, chain)"
    with tempfile.TemporaryDirectory() as d:
        path, m, u = _audit_fixture(Path(d))
        lines = path.read_text().splitlines()
        env = json.loads(lines[2])
        for field, value in (("ct", env["ct"][:-2] + ("AA" if env["ct"][-2:] != "AA" else "BB")), ("seq", 7)):
            bad = {**env, field: value}
            try:
                open_envelope(bad, m, u)
                return name, False, f"modified {field} still decrypted"
            except Exception:  # noqa: S112
                continue
        lines[2] = json.dumps({**env, "kid_m": "ffffffffffffffff"})
        path.write_text("\n".join(lines) + "\n")
        if verify_chain(path).ok:
            return name, False, "edited record passed chain verification"
        try:
            list(open_log(path, m, u))
            return name, False, "decrypter opened a broken chain"
        except ValueError:
            return name, True, ""


def check_padding_buckets() -> Check:
    name = "record sizes padded to fixed buckets"
    with tempfile.TemporaryDirectory() as d:
        path, _, _ = _audit_fixture(Path(d))
        sizes = {len(json.loads(line)["ct"]) for line in path.read_text().splitlines()}
        return name, len(sizes) == 1, f"ciphertext sizes {sorted(sizes)}; buckets {BUCKETS}"


def check_round_trip(n: int) -> Check:
    """R3 + stability: provider output → restore → resend → masks back byte-identically."""
    name = f"R3 round trip and turn stability on {n} synthetic conversations"
    eng = Engine(TokenKey.generate())
    for i, item in enumerate(Generator(4242).items(n)):
        conv = [Message("user", item.text)]
        first = eng.mask(conv, f"c{i}")
        reply = "Noted: " + first.messages[0].text
        rr = eng.restore(reply, first.vault)
        restored = rr.text
        if first.findings and (rr.restored == 0 or restored == reply):
            return (
                name,
                False,
                f"item {item.id}: nothing was restored (a no-op restore would pass R3 trivially)",
            )
        second = eng.mask(conv + [Message("assistant", restored)], f"c{i}")
        if second.messages[0].text != first.messages[0].text:
            return name, False, f"item {item.id}: masked user text changed between turns"
        if second.messages[1].text != reply:
            return name, False, f"item {item.id}: resent history did not mask back to the provider's bytes"
    return name, True, ""


def check_closed_world() -> Check:
    name = "restore is closed-world (foreign tokens untouched)"
    eng = Engine(TokenKey.generate(), form="token")
    res = eng.mask([Message("user", "card 4111 1111 1111 1111")], "c")
    out = eng.restore("see <CARD_aaaaaaaaaa> and <NRIC_bbbbbbbbbb>", res.vault)
    return name, out.restored == 0 and out.misses == 2, f"restored={out.restored} misses={out.misses}"


def check_surrogate_guarantees(n: int) -> Check:
    name = "surrogates: G2 fail their checksum, G1 in reserved ranges, never equal a real value"
    eng = Engine(TokenKey.generate())
    for i, item in enumerate(Generator(77).items(n)):
        res = eng.mask([Message("user", item.text)], f"g{i}")
        for (etype, real), entry in res.vault.entries.items():
            s = entry.surrogate.canonical
            if s == real:
                return name, False, f"{etype} surrogate equals the real value"
            bad = (
                (etype is EntityType.NRIC and nric_valid(s))
                or (etype is EntityType.IBAN and iban_valid(s))
                or (etype is EntityType.CARD and luhn_valid(s))
                or (etype is EntityType.EMAIL and not s.rsplit("@", 1)[1].startswith("example."))
                or (etype is EntityType.IPV4 and not s.startswith(("192.0.2.", "198.51.100.", "203.0.113.")))
                or (etype is EntityType.IPV6 and not s.startswith("2001:db8:"))
            )
            if bad:
                return name, False, f"{etype} surrogate breaks its guarantee"
    return name, True, ""


def check_policy_rails() -> Check:
    name = "policy schema rejects lab-only settings outside lab"
    sch = policy.schema("policy")
    for bad in (
        {"profile": "team", "audit": {"second_part": "dev_passphrase"}},
        {"profile": "personal", "on_error": "pass_and_log"},
    ):
        try:
            jsonschema.validate(bad, sch)
            return name, False, f"accepted {bad}"
        except jsonschema.ValidationError:
            continue
    jsonschema.validate({"profile": "lab", "audit": {"second_part": "dev_passphrase"}}, sch)
    return name, True, ""


def check_detection_floor(n: int) -> Check:
    name = "Stage 1 detection floor (recall >= 0.99 per in-scope type, phone_context=optional)"
    rep = bench.run(max(n, 500))
    low = {t: round(s.recall, 3) for t, s in rep.by_type.items() if s.recall < 0.99}
    return name, not low, f"below floor: {low}" if low else ""


def run_all(n: int = 300) -> list[Check]:
    checks: list[Callable[[], Check]] = [
        check_dev_key_refused,
        check_one_part_fails,
        check_no_breadcrumbs,
        check_tamper_detected,
        check_padding_buckets,
        lambda: check_round_trip(n),
        check_closed_world,
        lambda: check_surrogate_guarantees(n),
        check_policy_rails,
        lambda: check_detection_floor(n),
    ]
    out: list[Check] = []
    for c in checks:
        try:
            out.append(c())
        except Exception as e:  # a crashing check is a failed check
            out.append((getattr(c, "__name__", "check"), False, f"error: {type(e).__name__}: {e}"))
    return out

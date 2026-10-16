"""Conformance: the sealed audit (ADR-0004, ADR-0009, ADR-0010, invariants 6-7), checked against its claims.

See tests/conformance/test_claims_engine.py for the C-nn / F-nn convention. Synthetic records only.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from prompt_privacy.audit.envelope import open_with_shares, unwrap_token
from prompt_privacy.audit.keys import AuditKeyPair, dev_token_keypair, read_private, write_private
from prompt_privacy.audit.log import AuditLog, DevKeyRefused, open_log, read_envelopes, verify_chain
from prompt_privacy.cli.main import main
from prompt_privacy.core.keys import TokenKey


def _log(tmp: Path, n: int = 5) -> tuple[Path, AuditKeyPair, AuditKeyPair]:
    m, u = AuditKeyPair.generate(), AuditKeyPair.generate()
    log = AuditLog(tmp / "a.jsonl", m.public, u.public, "lab")
    for i in range(n):
        log.append({"event": "observe", "i": i})
    return tmp / "a.jsonl", m, u


def _write(path: Path, envs: list[dict[str, object]]) -> None:
    path.write_text("".join(json.dumps(e, separators=(",", ":")) + "\n" for e in envs))


def test_c23_token_share_alone_reveals_nothing(tmp_path: Path) -> None:
    """C-23 (ADR-0010 2-of-2: 'either share alone carries no information about DEK'): the token holder
    alone cannot decrypt (mutant M15 is caught only indirectly by the existing tests)."""
    path, _, u = _log(tmp_path, 1)
    env = next(read_envelopes(path))
    s2 = unwrap_token(env, u)
    with pytest.raises(Exception):  # noqa: B017 — any failure is the expected outcome
        open_with_shares(env, bytes(32), s2)


def test_c24_wrap_cannot_be_moved_to_another_record(tmp_path: Path) -> None:
    """C-24 (ADR-0010: header bound into both wraps and the AEAD)."""
    path, m, u = _log(tmp_path, 2)
    e1, e2 = list(read_envelopes(path))
    from prompt_privacy.audit.envelope import open_envelope

    for field in ("w_m", "w_u", "ct"):
        with pytest.raises(Exception):  # noqa: B017
            open_envelope({**e2, field: e1[field]}, m, u)


@pytest.mark.xfail(strict=True, reason="F-07: buckets 256/1K/4K/16K reveal event type and identifier volume")
def test_c25_record_size_does_not_reveal_event_type_or_volume(tmp_path: Path) -> None:
    """C-25 (ADR-0010: 'record sizes don't fingerprint event types'; principle: not 'how much')."""
    m, u = AuditKeyPair.generate(), AuditKeyPair.generate()
    log = AuditLog(tmp_path / "a.jsonl", m.public, u.public, "lab")
    log.append({"event": "digest_key", "kid": "0" * 16, "k_dig": "ab" * 32})
    item = {"t": "EMAIL", "c": "direct_identifier", "det": "rules.patterns", "d": "f" * 32}
    for n in (0, 10, 60):
        log.append({"event": "observe", "flow": "prompt", "new": [item] * n})
    sizes = {len(e["ct"]) for e in read_envelopes(tmp_path / "a.jsonl")}
    assert len(sizes) == 1, sorted(sizes)


def test_c26_dev_token_refused_outside_lab_and_marked(tmp_path: Path) -> None:
    """C-26 (invariant 6; ADR-0010 'kid_u = dev-1234 in the clear header')."""
    m = AuditKeyPair.generate()
    for profile in ("personal", "team", "regulated", "high-assurance", "LAB"):
        with pytest.raises(DevKeyRefused):
            AuditLog(tmp_path / f"{profile}.jsonl", m.public, dev_token_keypair().public, profile)
    log = AuditLog(tmp_path / "lab.jsonl", m.public, dev_token_keypair().public, "lab")
    assert log.append({"event": "x"})["kid_u"] == "dev-1234"


def test_c27_private_key_files_must_be_0600(tmp_path: Path) -> None:
    """C-27 (ADR-0003/0010 key custody, dev profile: 0600 files): readable-by-others keys are refused
    (mutants M18/M19 survived the review: the checks work but were untested)."""
    kp = AuditKeyPair.generate()
    write_private(tmp_path / "m.key", kp)
    assert (tmp_path / "m.key").stat().st_mode & 0o777 == 0o600
    assert read_private(tmp_path / "m.key").seed == kp.seed
    os.chmod(tmp_path / "m.key", 0o640)
    with pytest.raises(PermissionError):
        read_private(tmp_path / "m.key")
    tk = TokenKey.load_or_create(tmp_path / "t.key")
    assert (tmp_path / "t.key").stat().st_mode & 0o777 == 0o600
    assert TokenKey.load_or_create(tmp_path / "t.key").key == tk.key
    os.chmod(tmp_path / "t.key", 0o604)
    with pytest.raises(PermissionError):
        TokenKey.load_or_create(tmp_path / "t.key")


@pytest.mark.parametrize("attack", ["modify", "reorder", "delete-middle", "insert-forged-middle"])
def test_c28_chain_detects_edits_inside_the_log(tmp_path: Path, attack: str) -> None:
    """C-28 (ADR-0004 hash chain; invariant 7)."""
    path, m, u = _log(tmp_path, 5)
    envs = list(read_envelopes(path))
    if attack == "modify":
        envs[2] = {**envs[2], "ct": envs[1]["ct"]}
    elif attack == "reorder":
        envs[1], envs[2] = envs[2], envs[1]
    elif attack == "delete-middle":
        del envs[2]
    else:
        envs.insert(2, dict(envs[2]))
    _write(path, envs)
    assert not verify_chain(path).ok
    with pytest.raises(ValueError):
        list(open_log(path, m, u))


@pytest.mark.parametrize("attack", ["truncate-tail", "rewrite-with-public-keys"])
@pytest.mark.xfail(strict=True, reason="F-03: no signed checkpoints / writer authentication yet")
def test_c29_tamper_evident_against_truncation_and_rewrite(tmp_path: Path, attack: str) -> None:
    """C-29 (README: 'tamper-evident, attacker-proof evidence'). Writers hold only public keys, so a
    party with write access can drop the tail or forge a whole new history that verifies and opens."""
    path, m, u = _log(tmp_path, 5)
    if attack == "truncate-tail":
        _write(path, list(read_envelopes(path))[:3])
    else:
        path.unlink()
        AuditLog(path, m.public, u.public, "lab").append({"event": "observe", "note": "fabricated"})
    assert not verify_chain(path).ok


@pytest.mark.xfail(strict=True, reason="F-11: no file lock; each writer keeps its own seq/prev")
def test_c30_two_writers_keep_the_chain_valid(tmp_path: Path) -> None:
    """C-30 (invariant 7 'integrity chain always on'): e.g. `ppe serve` plus `ppe audit append`."""
    m, u = AuditKeyPair.generate(), AuditKeyPair.generate()
    a = AuditLog(tmp_path / "a.jsonl", m.public, u.public, "lab")
    b = AuditLog(tmp_path / "a.jsonl", m.public, u.public, "lab")
    for i in range(3):
        a.append({"event": "a", "i": i})
        b.append({"event": "b", "i": i})
    assert verify_chain(tmp_path / "a.jsonl").ok


@pytest.mark.xfail(strict=True, reason="F-11: a torn final line raises JSONDecodeError in verify and reopen")
def test_c31_torn_final_line_is_reported_not_fatal(tmp_path: Path) -> None:
    """C-31 (robustness of evidence): a crash mid-append leaves a partial line; verify reports it and the
    writer can resume (today `ppe audit verify` and `ppe serve` both crash)."""
    path, m, u = _log(tmp_path, 2)
    with path.open("a") as f:
        f.write('{"v":2,"seq":2,"prev":"ab')
    result = verify_chain(path)
    assert not result.ok and "torn" in result.error.lower()
    AuditLog(path, m.public, u.public, "lab").append({"event": "after-crash"})


def test_c32_observation_digest_bound_to_type(tmp_path: Path) -> None:
    """C-32 (ADR-0009: digest = HMAC(k, type ‖ value)): the same normalised value under two types gives
    two digests (mutant M21 survived the review)."""
    from prompt_privacy.proxy.observe import Observer

    m, u = AuditKeyPair.generate(), AuditKeyPair.generate()
    obs = Observer(AuditLog(tmp_path / "a.jsonl", m.public, u.public, "lab"))
    assert obs._digest("PHONE", "91234567") != obs._digest("CARD", "91234567")


def test_c26_cli_rails_end_to_end(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """C-26 via the CLI: keygen -> append -> verify -> open works in lab; the dev token is refused for
    any other profile; open with the wrong machine key fails."""
    d, log = str(tmp_path / "k"), str(tmp_path / "k" / "a.jsonl")
    assert main(["audit", "keygen", "--dir", d, "--dev-token"]) == 0
    assert main(["audit", "append", '{"event":"demo","n":1}', "--dir", d, "--log", log]) == 0
    with pytest.raises(DevKeyRefused):
        main(["audit", "append", '{"event":"demo"}', "--dir", d, "--log", log, "--profile", "personal"])
    assert main(["audit", "verify", "--log", log]) == 0
    capsys.readouterr()
    assert (
        main(["audit", "open", "--dir", d, "--log", log, "--machine-key", f"{d}/machine.key", "--dev-token"])
        == 0
    )
    assert '"demo"' in capsys.readouterr().out
    write_private(tmp_path / "wrong.key", AuditKeyPair.generate())
    with pytest.raises(Exception):  # noqa: B017
        main(
            [
                "audit",
                "open",
                "--dir",
                d,
                "--log",
                log,
                "--machine-key",
                str(tmp_path / "wrong.key"),
                "--dev-token",
            ]
        )

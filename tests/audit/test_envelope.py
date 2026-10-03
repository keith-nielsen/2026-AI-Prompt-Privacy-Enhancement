import json
from pathlib import Path

import pytest

from prompt_privacy.audit.envelope import open_envelope, seal
from prompt_privacy.audit.keys import AuditKeyPair, dev_token_keypair
from prompt_privacy.audit.log import GENESIS, AuditLog, DevKeyRefused, open_log, verify_chain


def test_round_trip_and_header_only_in_clear() -> None:
    m, u = AuditKeyPair.generate(), AuditKeyPair.generate()
    env = seal({"caller": "svc-x", "class": "special"}, 0, GENESIS, m.public, u.public)
    assert set(env) == {"v", "alg", "seq", "prev", "kid_m", "kid_u", "w_m", "w_u", "nonce", "ct"}
    assert "svc-x" not in json.dumps(env)
    assert open_envelope(env, m, u) == {"caller": "svc-x", "class": "special"}


def test_needs_both_parts() -> None:
    m, u, x = AuditKeyPair.generate(), AuditKeyPair.generate(), AuditKeyPair.generate()
    env = seal({"a": 1}, 0, GENESIS, m.public, u.public)
    for a, b in ((m, x), (x, u), (u, m)):
        with pytest.raises(Exception):  # noqa: B017 — any failure is correct here
            open_envelope(env, a, b)


def test_dev_token_is_deterministic_and_marked() -> None:
    assert dev_token_keypair().public.kid == "dev-1234"
    assert AuditKeyPair.from_passphrase("1234", b"ppe-dev-token-v1").seed == dev_token_keypair().seed


def test_dev_token_refused_outside_lab(tmp_path: Path) -> None:
    with pytest.raises(DevKeyRefused):
        AuditLog(tmp_path / "a.jsonl", AuditKeyPair.generate().public, dev_token_keypair().public, "personal")


def test_chain_append_reopen_verify(tmp_path: Path) -> None:
    m, u = AuditKeyPair.generate(), dev_token_keypair()
    p = tmp_path / "a.jsonl"
    AuditLog(p, m.public, u.public, "lab").append({"n": 1})
    AuditLog(p, m.public, u.public, "lab").append({"n": 2})  # reopen continues the chain
    assert verify_chain(p).ok and verify_chain(p).count == 2
    assert [r["n"] for r in open_log(p, m, u)] == [1, 2]
    lines = p.read_text().splitlines()
    p.write_text(lines[1] + "\n" + lines[0] + "\n")  # reorder
    assert not verify_chain(p).ok

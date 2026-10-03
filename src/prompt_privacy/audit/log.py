"""Append-only, hash-chained log of sealed envelopes (ADR-0004 integrity, ADR-0010 sealing).

The chain covers envelopes, so integrity is verifiable by anyone; contents by nobody without both
key parts. Signed checkpoints (C2SP tlog-checkpoint) are a later step.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from prompt_privacy.audit.envelope import canonical, open_envelope, seal
from prompt_privacy.audit.keys import DEV_TOKEN_KID, AuditKeyPair, AuditPublicKey

GENESIS = "0" * 64


def envelope_hash(env: dict[str, Any]) -> str:
    return hashlib.sha256(canonical(env)).hexdigest()


class DevKeyRefused(RuntimeError):
    pass


class AuditLog:
    """Writer. Holds public keys only."""

    def __init__(
        self, path: Path, pk_machine: AuditPublicKey, pk_token: AuditPublicKey, profile: str
    ) -> None:
        if pk_token.kid == DEV_TOKEN_KID and profile != "lab":
            raise DevKeyRefused('the development token key ("1234") is only allowed in the lab profile')
        self.path, self.pk_m, self.pk_u, self.profile = path, pk_machine, pk_token, profile
        self._seq, self._prev = 0, GENESIS
        if path.exists():
            last = None
            for env in read_envelopes(path):
                last = env
            if last is not None:
                self._seq, self._prev = last["seq"] + 1, envelope_hash(last)

    def append(self, record: dict[str, Any]) -> dict[str, Any]:
        env = seal({**record, "profile": self.profile}, self._seq, self._prev, self.pk_m, self.pk_u)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as f:
            f.write(json.dumps(env, separators=(",", ":")) + "\n")
            f.flush()
            os.fsync(f.fileno())
        self._seq, self._prev = self._seq + 1, envelope_hash(env)
        return env


def read_envelopes(path: Path) -> Iterator[dict[str, Any]]:
    with path.open() as f:
        for line in f:
            if line.strip():
                yield json.loads(line)


@dataclass
class VerifyResult:
    ok: bool
    count: int
    error: str = ""


def verify_chain(path: Path) -> VerifyResult:
    prev, n = GENESIS, 0
    for env in read_envelopes(path):
        if env.get("seq") != n:
            return VerifyResult(False, n, f"sequence gap at record {n} (found {env.get('seq')})")
        if env.get("prev") != prev:
            return VerifyResult(False, n, f"chain broken at record {n}")
        prev, n = envelope_hash(env), n + 1
    return VerifyResult(True, n)


def open_log(path: Path, sk_machine: AuditKeyPair, sk_token: AuditKeyPair) -> Iterator[dict[str, Any]]:
    """The audit-grade decrypter's view: verifies the chain first, then opens every record."""
    v = verify_chain(path)
    if not v.ok:
        raise ValueError(f"audit chain verification failed: {v.error}")
    for env in read_envelopes(path):
        yield {"seq": env["seq"], **open_envelope(env, sk_machine, sk_token)}

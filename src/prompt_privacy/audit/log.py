"""Append-only, hash-chained log of sealed envelopes (ADR-0004 integrity, ADR-0010 sealing).

The chain covers envelopes, so integrity is verifiable by anyone; contents by nobody without both
key parts. Signed checkpoints (C2SP tlog-checkpoint) are a later step: until then the chain detects edits
inside the log, not truncation of its tail or a log rebuilt from scratch (review F-03).

Several writers may share one file (`ppe serve` plus `ppe audit append`): every append takes an exclusive
`flock` and reads the chain state from the file's last record, never from memory. A crash mid-append
leaves a torn last line; the next writer cuts it off and records a sealed `recovered` event with the
fragment's length and SHA-256 before its own record, and `verify_chain` reports a torn tail as such.
"""

from __future__ import annotations

import fcntl
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

    def append(self, record: dict[str, Any]) -> dict[str, Any]:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            last, torn_at, torn = _tail(fd)
            seq, prev = (last["seq"] + 1, envelope_hash(last)) if last is not None else (0, GENESIS)
            if torn:
                os.ftruncate(fd, torn_at)
                note = {"event": "recovered", "torn_bytes": len(torn), "torn_sha256": _sha256(torn)}
                prev = envelope_hash(self._write(fd, note, seq, prev))
                seq += 1
            return self._write(fd, record, seq, prev)
        finally:
            os.close(fd)  # releases the lock

    def _write(self, fd: int, record: dict[str, Any], seq: int, prev: str) -> dict[str, Any]:
        env = seal({**record, "profile": self.profile}, seq, prev, self.pk_m, self.pk_u)
        data = (json.dumps(env, separators=(",", ":")) + "\n").encode()
        while data:
            data = data[os.write(fd, data) :]
        os.fsync(fd)
        return env


_TAIL_BLOCK = 64 * 1024


def _sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _tail(fd: int) -> tuple[dict[str, Any] | None, int, bytes]:
    """(last complete envelope or None, offset of the torn fragment, torn fragment bytes)."""
    end = os.fstat(fd).st_size
    buf, pos = b"", end
    # Read backwards until the buffer holds the whole last complete line, i.e. the newline before it.
    while pos > 0:
        n = min(_TAIL_BLOCK, pos)
        pos -= n
        buf = os.pread(fd, n, pos) + buf
        if b"\n" in buf[: buf.rfind(b"\n") + 1].rstrip(b"\n"):
            break
    cut = buf.rfind(b"\n") + 1  # 0 when there is no newline at all: the whole file is one torn line
    torn = buf[cut:]
    torn_at = end - len(torn)
    complete = buf[:cut].rstrip(b"\n")
    if not complete.strip():
        return None, torn_at, torn
    line = complete[complete.rfind(b"\n") + 1 :]
    try:
        last = json.loads(line)
    except ValueError as e:
        raise ValueError("audit log's last complete record is unreadable; run `ppe audit verify`") from e
    return last, torn_at, torn


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
    with path.open("rb") as f:
        lines = f.read().split(b"\n")
    torn = lines.pop()  # bytes after the last newline: empty unless an append was cut short
    for i, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            env = json.loads(line)
        except ValueError:
            return VerifyResult(False, n, f"unreadable record at line {i}")
        if not isinstance(env, dict):
            return VerifyResult(False, n, f"unreadable record at line {i}")
        if env.get("seq") != n:
            return VerifyResult(False, n, f"sequence gap at record {n} (found {env.get('seq')})")
        if env.get("prev") != prev:
            return VerifyResult(False, n, f"chain broken at record {n}")
        prev, n = envelope_hash(env), n + 1
    if torn.strip():
        return VerifyResult(
            False, n, f"torn tail: {len(torn)} bytes after record {n - 1} (an append was cut short)"
        )
    return VerifyResult(True, n)


def open_log(path: Path, sk_machine: AuditKeyPair, sk_token: AuditKeyPair) -> Iterator[dict[str, Any]]:
    """The audit-grade decrypter's view: verifies the chain first, then opens every record."""
    v = verify_chain(path)
    if not v.ok:
        raise ValueError(f"audit chain verification failed: {v.error}")
    for env in read_envelopes(path):
        yield {"seq": env["seq"], **open_envelope(env, sk_machine, sk_token)}

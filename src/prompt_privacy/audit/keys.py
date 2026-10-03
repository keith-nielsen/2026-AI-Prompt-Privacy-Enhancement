"""Audit key pairs (ADR-0010): machine part and token part, hybrid ML-KEM-768 + X25519.

Writers hold public keys only. Private keys are 96-byte seeds (64-byte ML-KEM seed + 32-byte X25519).
The development token stand-in is derived from a passphrase (the string "1234") with Argon2id; it is
refused outside the `lab` profile (ADR-0012 invariant 6).
"""

from __future__ import annotations

import hashlib
import os
import secrets
from dataclasses import dataclass
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hpke
from cryptography.hazmat.primitives.asymmetric import mlkem, x25519

DEV_TOKEN_PASSPHRASE = "1234"  # noqa: S105 — the documented dev stand-in for the USB token (ADR-0010)
DEV_TOKEN_SALT = b"ppe-dev-token-v1"
DEV_TOKEN_KID = "dev-1234"  # noqa: S105 — a key-id label, not a secret

_MLKEM_PUB_LEN = 1184
_X25519_PUB_LEN = 32


@dataclass(frozen=True)
class AuditPublicKey:
    raw: bytes  # ML-KEM-768 public (1184) || X25519 public (32)

    def __post_init__(self) -> None:
        if len(self.raw) != _MLKEM_PUB_LEN + _X25519_PUB_LEN:
            raise ValueError("bad hybrid public key length")

    @property
    def kid(self) -> str:
        if self.raw == dev_token_keypair().public.raw:
            return DEV_TOKEN_KID
        return hashlib.sha256(b"ppe/audit-kid/v1" + self.raw).hexdigest()[:16]

    def to_hpke(self) -> hpke.MLKEM768X25519PublicKey:
        m = mlkem.MLKEM768PublicKey.from_public_bytes(self.raw[:_MLKEM_PUB_LEN])
        x = x25519.X25519PublicKey.from_public_bytes(self.raw[_MLKEM_PUB_LEN:])
        return hpke.MLKEM768X25519PublicKey(m, x)


@dataclass(frozen=True)
class AuditKeyPair:
    seed: bytes  # 96 bytes

    def __post_init__(self) -> None:
        if len(self.seed) != 96:
            raise ValueError("audit key seed must be 96 bytes")

    def _parts(self) -> tuple[mlkem.MLKEM768PrivateKey, x25519.X25519PrivateKey]:
        return (
            mlkem.MLKEM768PrivateKey.from_seed_bytes(self.seed[:64]),
            x25519.X25519PrivateKey.from_private_bytes(self.seed[64:]),
        )

    def to_hpke(self) -> hpke.MLKEM768X25519PrivateKey:
        m, x = self._parts()
        return hpke.MLKEM768X25519PrivateKey(m, x)

    @property
    def public(self) -> AuditPublicKey:
        m, x = self._parts()
        return AuditPublicKey(m.public_key().public_bytes_raw() + x.public_key().public_bytes_raw())

    @classmethod
    def generate(cls) -> AuditKeyPair:
        return cls(secrets.token_bytes(96))

    @classmethod
    def from_passphrase(cls, passphrase: str, salt: bytes) -> AuditKeyPair:
        seed = hash_secret_raw(
            passphrase.encode(),
            salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=1,
            hash_len=96,
            type=Type.ID,
        )
        return cls(seed)


_DEV_CACHE: list[AuditKeyPair] = []


def dev_token_keypair() -> AuditKeyPair:
    """The development token part, derived from "1234". Cached: Argon2id costs ~0.1 s."""
    if not _DEV_CACHE:
        _DEV_CACHE.append(AuditKeyPair.from_passphrase(DEV_TOKEN_PASSPHRASE, DEV_TOKEN_SALT))
    return _DEV_CACHE[0]


def write_private(path: Path, kp: AuditKeyPair) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(kp.seed)


def read_private(path: Path) -> AuditKeyPair:
    if path.stat().st_mode & 0o077:
        raise PermissionError(f"{path} must not be readable by group/other (chmod 600)")
    return AuditKeyPair(path.read_bytes())

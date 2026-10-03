"""Token-epoch key handling (ADR-0002 / ADR-0003)."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass
from pathlib import Path


def lp(data: bytes | str) -> bytes:
    """Length-prefixed encoding: unambiguous concatenation of fields."""
    b = data.encode() if isinstance(data, str) else data
    return len(b).to_bytes(4, "big") + b


def key_id(key: bytes) -> str:
    return hashlib.sha256(b"ppe/kid/v1" + key).hexdigest()[:16]


@dataclass(frozen=True)
class TokenKey:
    """`k_tok[e]`: seeds surrogates/tokens and conversation scopes for one epoch."""

    key: bytes

    def __post_init__(self) -> None:
        if len(self.key) != 32:
            raise ValueError("token key must be 32 bytes")

    @property
    def kid(self) -> str:
        return key_id(self.key)

    def mac(self, label: str, *fields: bytes | str) -> bytes:
        return hmac.new(self.key, label.encode() + b"".join(lp(f) for f in fields), hashlib.sha256).digest()

    def scope(self, conversation_key: str) -> str:
        """Keyed conversation scope; the raw conversation id is never used directly."""
        return self.mac("ppe/scope/v1", conversation_key).hex()[:32]

    @classmethod
    def generate(cls) -> TokenKey:
        return cls(secrets.token_bytes(32))

    @classmethod
    def load_or_create(cls, path: Path) -> TokenKey:
        if path.exists():
            if path.stat().st_mode & 0o077:
                raise PermissionError(f"{path} must not be readable by group/other (chmod 600)")
            return cls(path.read_bytes())
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        key = cls.generate()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key.key)
        return key

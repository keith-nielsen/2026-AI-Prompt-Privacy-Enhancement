"""Fully sealed audit envelope (ADR-0010): nothing readable without BOTH key parts.

    DEK  = random 32 bytes;   ct = AES-256-GCM(DEK, padded record, aad = header)
    s1   = random 32 bytes;   s2 = DEK xor s1           (2-of-2 split)
    w_m  = HPKE(pk_machine, s1, info = label_m || header)
    w_u  = HPKE(pk_token,   s2, info = label_u || header)

HPKE suite: ML-KEM-768 + X25519 hybrid KEM, HKDF-SHA256, AES-256-GCM (post-quantum, H11).
The header is bound into both wraps and the AEAD, so no part can be moved to another record.
"""

from __future__ import annotations

import base64
import json
import secrets
from typing import Any

from cryptography.hazmat.primitives import hpke
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from prompt_privacy.audit.keys import AuditKeyPair, AuditPublicKey

ENVELOPE_VERSION = 2
ALG = "hpke-mlkem768x25519-hkdfsha256-aes256gcm+aes256gcm"
_SUITE = hpke.Suite(hpke.KEM.MLKEM768_X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.AES_256_GCM)
_LABEL_M = b"ppe/audit/v2/machine|"
_LABEL_U = b"ppe/audit/v2/token|"
BUCKETS = (256, 1024, 4096, 16384)  # padded plaintext sizes; sizes don't fingerprint event types


def canonical(obj: Any) -> bytes:
    """Canonical JSON (sorted keys, no whitespace, UTF-8). Sufficient for our ASCII/integer records."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _pad(data: bytes) -> bytes:
    framed = len(data).to_bytes(4, "big") + data
    for size in BUCKETS:
        if len(framed) <= size:
            return framed + b"\x00" * (size - len(framed))
    raise ValueError(f"audit record too large ({len(data)} bytes)")


def _unpad(data: bytes) -> bytes:
    n = int.from_bytes(data[:4], "big")
    return data[4 : 4 + n]


def header_of(env: dict[str, Any]) -> dict[str, Any]:
    return {k: env[k] for k in ("v", "alg", "seq", "prev", "kid_m", "kid_u")}


def seal(
    record: dict[str, Any], seq: int, prev: str, pk_machine: AuditPublicKey, pk_token: AuditPublicKey
) -> dict[str, Any]:
    header = {
        "v": ENVELOPE_VERSION,
        "alg": ALG,
        "seq": seq,
        "prev": prev,
        "kid_m": pk_machine.kid,
        "kid_u": pk_token.kid,
    }
    hb = canonical(header)
    dek, nonce, s1 = secrets.token_bytes(32), secrets.token_bytes(12), secrets.token_bytes(32)
    s2 = bytes(a ^ b for a, b in zip(dek, s1, strict=True))
    ct = AESGCM(dek).encrypt(nonce, _pad(canonical(record)), hb)
    return {
        **header,
        "w_m": _b64(_SUITE.encrypt(s1, pk_machine.to_hpke(), info=_LABEL_M + hb)),
        "w_u": _b64(_SUITE.encrypt(s2, pk_token.to_hpke(), info=_LABEL_U + hb)),
        "nonce": _b64(nonce),
        "ct": _b64(ct),
    }


def unwrap_machine(env: dict[str, Any], sk_machine: AuditKeyPair) -> bytes:
    return _SUITE.decrypt(_unb64(env["w_m"]), sk_machine.to_hpke(), info=_LABEL_M + canonical(header_of(env)))


def unwrap_token(env: dict[str, Any], sk_token: AuditKeyPair) -> bytes:
    return _SUITE.decrypt(_unb64(env["w_u"]), sk_token.to_hpke(), info=_LABEL_U + canonical(header_of(env)))


def open_with_shares(env: dict[str, Any], s1: bytes, s2: bytes) -> dict[str, Any]:
    """Combine the two shares (they may be unwrapped in different places) and decrypt."""
    dek = bytes(a ^ b for a, b in zip(s1, s2, strict=True))
    pt = AESGCM(dek).decrypt(_unb64(env["nonce"]), _unb64(env["ct"]), canonical(header_of(env)))
    result: dict[str, Any] = json.loads(_unpad(pt))
    return result


def open_envelope(env: dict[str, Any], sk_machine: AuditKeyPair, sk_token: AuditKeyPair) -> dict[str, Any]:
    return open_with_shares(env, unwrap_machine(env, sk_machine), unwrap_token(env, sk_token))

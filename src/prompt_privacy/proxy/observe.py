"""Shadow-mode observation of proxied requests (ADR-0007, sealed per ADR-0010): detect, digest, record.

Never modifies traffic. Each identifier is recorded as a keyed digest `HMAC(k_dig, type ‖ norm value)`;
`k_dig` is random per process and written to the audit once, sealed (`digest_key`, ADR-0009), so an
investigator with both audit parts can test a value; nobody online can. Values never reach the log.
Deduplicated per (conversation, digest): a client that resends its whole history every turn (Claude
Code does) records each identifier once. Text blocks already scanned are cached by content hash.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

from prompt_privacy.audit.log import AuditLog
from prompt_privacy.core.keys import key_id, lp
from prompt_privacy.core.normalise import NORM_VERSION, norm
from prompt_privacy.detectors.base import detect

PER_RECORD = 100  # findings per sealed record; keeps each record inside the 16 KB padding bucket
_MAX_CONVERSATIONS = 1024
_MAX_CACHED_BLOCKS = 4096


@dataclass(frozen=True, slots=True)
class Seen:
    type: str
    data_class: str
    detector: str
    digest: str


@dataclass
class Request:
    """What the proxy hands over: the body bytes plus routing facts (no headers beyond these)."""

    req_id: str
    method: str
    path: str
    body: bytes
    conversation: str | None
    zone: str  # loopback | cloud (the upstream's zone)


@dataclass
class Observer:
    log: AuditLog
    k_dig: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    dropped: int = 0  # requests not observed (backlog full); reported in the next record
    _seen: OrderedDict[str, set[str]] = field(default_factory=OrderedDict)
    _blocks: OrderedDict[bytes, tuple[Seen, ...]] = field(default_factory=OrderedDict)

    def __post_init__(self) -> None:
        self.log.append({"event": "digest_key", "kid": key_id(self.k_dig), "k_dig": self.k_dig.hex()})

    def _digest(self, etype: str, value_norm: str) -> str:
        msg = b"ppe/obs/v1" + lp(etype) + lp(value_norm)
        return hmac.new(self.k_dig, msg, hashlib.sha256).hexdigest()[:32]

    def _conv(self, conversation: str | None) -> str | None:
        if conversation is None:
            return None
        return hmac.new(self.k_dig, b"ppe/conv/v1" + lp(conversation), hashlib.sha256).hexdigest()[:32]

    def _scan_block(self, text: str) -> tuple[Seen, ...]:
        h = hashlib.sha256(text.encode("utf-8", "surrogatepass")).digest()
        hit = self._blocks.get(h)
        if hit is not None:
            self._blocks.move_to_end(h)
            return hit
        out = tuple(
            Seen(
                f.type.value,
                f.data_class.value,
                f.detector,
                self._digest(f.type.value, norm(f.type, f.value)),
            )
            for f in detect(text)
        )
        self._blocks[h] = out
        if len(self._blocks) > _MAX_CACHED_BLOCKS:
            self._blocks.popitem(last=False)
        return out

    def observe(self, req: Request) -> list[dict[str, Any]]:
        """Scan one request and append its sealed record(s). Returns the records (for tests)."""
        base: dict[str, Any] = {
            "event": "observe",
            "flow": "prompt",
            "zone": req.zone,
            "req_id": req.req_id,
            "method": req.method,
            "path": req.path,
            "conv": self._conv(req.conversation),
            "bytes": len(req.body),
            "ts": int(time.time()),
            "norm_v": NORM_VERSION,
            "kid": key_id(self.k_dig),
        }
        if self.dropped:
            base["dropped_before"], self.dropped = self.dropped, 0
        texts, model, reason = extract(req.path, req.body)
        base["scanned"] = reason is None
        if reason is not None:
            base["reason"] = reason
            return [self._append(base)]
        base["model"] = model
        base["skipped_blocks"] = texts.skipped
        found = [s for t in texts.texts for s in self._scan_block(t)]
        base["findings_total"] = len(found)
        key = base["conv"] or req.req_id
        seen = self._seen.setdefault(key, set())
        self._seen.move_to_end(key)
        if len(self._seen) > _MAX_CONVERSATIONS:
            self._seen.popitem(last=False)
        new: list[Seen] = []
        for s in found:
            if s.digest not in seen:
                seen.add(s.digest)
                new.append(s)
        parts = [new[i : i + PER_RECORD] for i in range(0, len(new), PER_RECORD)] or [[]]
        return [
            self._append(
                {
                    **base,
                    "part": i,
                    "parts": len(parts),
                    "new": [
                        {"t": s.type, "c": s.data_class, "det": s.detector, "d": s.digest} for s in chunk
                    ],
                }
            )
            for i, chunk in enumerate(parts)
        ]

    def _append(self, record: dict[str, Any]) -> dict[str, Any]:
        self.log.append(record)
        return record


@dataclass
class Texts:
    texts: list[str] = field(default_factory=list)
    skipped: int = 0  # content blocks of a kind Stage 1 cannot read (images, unknown types)


def extract(path: str, body: bytes) -> tuple[Texts, str | None, str | None]:
    """(texts, model, reason-not-scanned). Only the Anthropic Messages API is parsed in phase 2a."""
    if path.split("?", 1)[0].rstrip("/") not in ("/v1/messages", "/v1/messages/count_tokens"):
        return Texts(), None, "unsupported_path" if body else "no_body"
    try:
        doc = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return Texts(), None, "unparsable_body"
    if not isinstance(doc, dict):
        return Texts(), None, "unparsable_body"
    out = Texts()
    _collect(doc.get("system"), out)
    for m in doc.get("messages") or []:
        # Assistant turns are provider-authored: they are the reply flow (phase 2b), not the prompt.
        if isinstance(m, dict) and m.get("role") != "assistant":
            _collect(m.get("content"), out)
    model = doc.get("model")
    return out, model if isinstance(model, str) else None, None


def _collect(content: Any, out: Texts) -> None:
    if content is None:
        return
    if isinstance(content, str):
        out.texts.append(content)
        return
    if not isinstance(content, list):
        out.skipped += 1
        return
    for block in content:
        if isinstance(block, str):
            out.texts.append(block)
        elif not isinstance(block, dict):
            out.skipped += 1
        elif block.get("type") == "text" and isinstance(block.get("text"), str):
            out.texts.append(block["text"])
        elif block.get("type") == "tool_result":
            _collect(block.get("content"), out)
        elif (
            block.get("type") == "document"
            and isinstance(block.get("source"), dict)
            and isinstance(block["source"].get("data"), str)
            and block["source"].get("type") == "text"
        ):
            out.texts.append(block["source"]["data"])
        else:
            out.skipped += 1

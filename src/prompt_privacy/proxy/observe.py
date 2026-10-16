"""Shadow-mode observation of proxied requests (ADR-0007, sealed per ADR-0010): detect, digest, record.

Never modifies traffic. Each identifier is recorded as a keyed digest `HMAC(k_dig, type ‖ norm value)`;
`k_dig` is random per process and written to the audit once, sealed (`digest_key`, ADR-0009), so an
investigator with both audit parts can test a value; nobody online can. Values never reach the log.
Deduplicated per (conversation, digest): a client that resends its whole history every turn (Claude
Code does) records each identifier once. Text blocks already scanned are cached by content hash.

Every request yields a record: scanned, or not scanned with a reason code (a coverage gap, ADR-0007),
including when the scan itself fails. Compressed bodies are decoded here, on a bounded copy; the relay
forwards the original bytes. Request fields that reach the record (`model`, `path`) are bounded and
scanned like the body (they go upstream too); one that is too long or holds a finding is withheld.
Requests the observer could not see or record are counted and carried into the next record and into a
shutdown record (`observe_stop`).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
import zlib
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

from prompt_privacy.audit.log import AuditLog
from prompt_privacy.core.keys import key_id, lp
from prompt_privacy.core.normalise import NORM_VERSION, norm
from prompt_privacy.detectors.base import detect

PER_RECORD = 100  # findings per sealed record; keeps each record inside the 16 KB padding bucket
MAX_MODEL = 128  # longer `model` / `path` values are withheld from the record (bounded record size)
MAX_PATH = 256
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
    """What the proxy hands over: the body bytes plus routing facts. The only request headers passed
    are the conversation id and Content-Encoding (to decode a bounded copy)."""

    req_id: str
    method: str
    path: str
    body: bytes
    conversation: str | None
    zone: str  # loopback | cloud (the upstream's zone)
    encoding: str | None = None  # Content-Encoding as sent; the observer decodes a bounded copy
    query: str = ""  # decoded query string: scanned, never recorded


@dataclass
class Observer:
    log: AuditLog
    k_dig: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    max_decoded: int = 64 * 1024 * 1024  # cap on a decoded body; beyond it the request is a gap
    dropped: int = 0  # requests not observed (backlog full); carried into the next record / observe_stop
    failed: int = 0  # requests whose record could not be written at all; carried the same way
    observed: int = 0  # requests recorded as scanned
    gaps: int = 0  # requests recorded as not scanned (reason code)
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
        """Scan one request and append its sealed record(s). Returns the records (for tests).

        Never raises because of the request: a failing scan becomes a gap record with a reason code.
        Raises only if even that record cannot be written (the caller counts it in `failed`)."""
        base = self._base(req)
        carried: dict[str, Any] = {k: base[k] for k in ("dropped_before", "failed_before") if k in base}
        try:
            try:
                return self._observe(req, base)
            except Exception as e:  # any failure of the scan is a counted gap, never silent
                reason = "too_deep" if isinstance(e, RecursionError) else f"observer_error:{type(e).__name__}"
                gap = self._base(req) | carried | {"scanned": False, "reason": reason, "new": []}
                record = self._append(gap)
                self.gaps += 1
                return [record]
        except BaseException:
            # Nothing recorded: keep the carried counts for a later record (the caller adds this request).
            self.dropped += carried.get("dropped_before", 0)
            self.failed += carried.get("failed_before", 0)
            raise

    def _base(self, req: Request) -> dict[str, Any]:
        base: dict[str, Any] = {
            "event": "observe",
            "flow": "prompt",
            "zone": req.zone,
            "req_id": req.req_id,
            "method": req.method[:16],
            "conv": self._conv(req.conversation),
            "bytes": len(req.body),
            "ts": int(time.time()),
            "norm_v": NORM_VERSION,
            "kid": key_id(self.k_dig),
        }
        if self.dropped or self.failed:
            base["dropped_before"], base["failed_before"] = self.dropped, self.failed
            self.dropped = self.failed = 0
        return base

    def _bounded(self, value: str | None, limit: int) -> tuple[str | None, tuple[Seen, ...]]:
        """(value to record, findings in it). A value with a finding, or longer than `limit`, is withheld."""
        if value is None:
            return None, ()
        found = self._scan_block(value)
        if found or len(value) > limit:
            return f"<withheld:{len(value)}>", found
        return value, ()

    def _observe(self, req: Request, base: dict[str, Any]) -> list[dict[str, Any]]:
        carried: dict[str, Any] = {k: base.pop(k) for k in ("dropped_before", "failed_before") if k in base}
        base["path"], found_path = self._bounded(req.path, MAX_PATH)
        found = list(found_path)
        if req.query:
            found += self._scan_block(req.query)
        body, reason = decode(req.body, req.encoding, self.max_decoded)
        texts, model = Texts(), None
        if reason is None:
            assert body is not None
            texts, model, reason = extract(req.path, body)
        base["scanned"] = reason is None
        if reason is not None:
            base["reason"] = reason
        else:
            base["model"], found_model = self._bounded(model, MAX_MODEL)
            base["skipped_blocks"] = texts.skipped
            found += found_model
            found += [s for t in texts.texts for s in self._scan_block(t)]
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
        records = [
            self._append(
                {
                    **base,
                    **(carried if i == 0 else {}),  # counts carried once, not once per part
                    "part": i,
                    "parts": len(parts),
                    "new": [
                        {"t": s.type, "c": s.data_class, "det": s.detector, "d": s.digest} for s in chunk
                    ],
                }
            )
            for i, chunk in enumerate(parts)
        ]
        if reason is None:
            self.observed += 1
        else:
            self.gaps += 1
        return records

    def health(self) -> dict[str, int]:
        return {"observed": self.observed, "gaps": self.gaps, "dropped": self.dropped, "failed": self.failed}

    def stop(self) -> dict[str, int]:
        """Shutdown record: totals, including drops/failures not yet carried by a later record."""
        health = self.health()
        self._append({"event": "observe_stop", "ts": int(time.time()), **health})
        self.dropped = self.failed = 0
        return health

    def _append(self, record: dict[str, Any]) -> dict[str, Any]:
        self.log.append(record)
        return record


@dataclass
class Texts:
    texts: list[str] = field(default_factory=list)
    skipped: int = 0  # content blocks of a kind Stage 1 cannot read (images, unknown types)


class _TooLarge(Exception):
    pass


def decode(body: bytes, encoding: str | None, cap: int) -> tuple[bytes | None, str | None]:
    """Undo Content-Encoding on a copy, never producing more than `cap` bytes: (body, None) or
    (None, reason). gzip/x-gzip/deflate are decoded; other codings (br, zstd, ...) are a gap."""
    codings = [c.strip().lower() for c in (encoding or "").split(",") if c.strip()]
    try:
        for c in reversed(codings):  # applied in listed order, so undone in reverse
            if c == "identity":
                continue
            if c in ("gzip", "x-gzip"):
                body = _inflate(body, 16 + zlib.MAX_WBITS, cap, members=True)
            elif c == "deflate":  # RFC 9110: zlib-wrapped; some clients send raw deflate
                try:
                    body = _inflate(body, zlib.MAX_WBITS, cap)
                except zlib.error:
                    body = _inflate(body, -zlib.MAX_WBITS, cap)
            else:
                return None, "unsupported_encoding"
    except _TooLarge:
        return None, "decoded_too_large"
    except zlib.error:
        return None, "undecodable_body"
    return body, None


def _inflate(data: bytes, wbits: int, cap: int, members: bool = False) -> bytes:
    out = bytearray()
    d = zlib.decompressobj(wbits)
    while True:
        out += d.decompress(data, cap + 1 - len(out))
        if len(out) > cap:
            raise _TooLarge
        if d.unconsumed_tail:  # stopped at the output limit, input left
            data = d.unconsumed_tail
            continue
        if not d.eof:
            raise zlib.error("truncated stream")
        if not d.unused_data.strip(b"\0"):
            return bytes(out)
        if not members:
            raise zlib.error("data after end of stream")
        data, d = d.unused_data, zlib.decompressobj(wbits)  # next gzip member


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

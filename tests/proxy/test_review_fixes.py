"""Regression tests for the 2026-10-16 review fixes to `ppe serve`: compressed request bodies (F-04),
no request bytes in logs or error bodies (F-05), every request recorded or counted (F-06), and the
listener's Host/Origin checks (F-08). Fake upstream on loopback only; synthetic data only."""

from __future__ import annotations

import asyncio
import gzip
import json
import logging
import random
import tracemalloc
import zlib
from collections.abc import AsyncIterator, Coroutine
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from prompt_privacy.audit.keys import AuditKeyPair
from prompt_privacy.audit.log import AuditLog, open_log, verify_chain
from prompt_privacy.proxy import app as proxy
from prompt_privacy.proxy.observe import MAX_MODEL, PER_RECORD, Observer, Request, decode
from tests.proxy.support import ProxyTestServer

NRIC = "S1234567D"  # widely published sample value
LOCAL = "Host: 127.0.0.1\r\n"


def run(coro: Coroutine[Any, Any, None]) -> None:
    asyncio.run(coro)


def body(text: str, model: str = "claude-test") -> bytes:
    return json.dumps({"model": model, "messages": [{"role": "user", "content": text}]}).encode()


class Stack:
    """Raw upstream (no decompression) + proxy + sealed audit."""

    def __init__(self, tmp: Path) -> None:
        self.tmp, self.seen = tmp, []  # type: ignore[var-annotated]
        self.m, self.u = AuditKeyPair.generate(), AuditKeyPair.generate()

    async def _h(self, r: web.Request) -> web.Response:
        self.seen.append((r.headers.copy(), await r.read()))
        return web.Response(body=b'{"ok":true}', content_type="application/json")

    @asynccontextmanager
    async def run(self, **settings: Any) -> AsyncIterator[TestClient]:
        upa = web.Application(client_max_size=1 << 30, handler_args={"auto_decompress": False})
        upa.router.add_route("*", "/{t:.*}", self._h)
        up = TestServer(upa, host="127.0.0.1")
        await up.start_server(access_log=None)  # the fake upstream's log would show forwarded paths
        self.observer = Observer(AuditLog(self.tmp / "a.jsonl", self.m.public, self.u.public, "lab"))
        upstream = str(up.make_url("/")).rstrip("/")
        app = proxy.build_app(proxy.Settings(upstream=upstream, **settings), self.observer)
        client = TestClient(ProxyTestServer(app, host="127.0.0.1"))
        await client.start_server()
        try:
            yield client
        finally:
            await client.close()
            await up.close()

    def records(self) -> list[dict[str, Any]]:
        assert verify_chain(self.tmp / "a.jsonl").ok
        return list(open_log(self.tmp / "a.jsonl", self.m, self.u))

    def observed(self) -> list[dict[str, Any]]:
        return [r for r in self.records() if r["event"] == "observe"]


async def raw(port: int, payload: bytes) -> bytes:
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(payload)
    await w.drain()
    data = b""
    while True:
        try:
            chunk = await asyncio.wait_for(r.read(65536), 0.3)
        except TimeoutError:
            break
        if not chunk:
            break
        data += chunk
    w.close()
    return data


# --- F-04: compressed request bodies ---------------------------------------------------------------


def _raw_deflate(b: bytes) -> bytes:
    c = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    return c.compress(b) + c.flush()


@pytest.mark.parametrize(
    ("encoding", "encode", "scanned"),
    [
        ("gzip", gzip.compress, True),
        ("x-gzip", gzip.compress, True),
        ("deflate", zlib.compress, True),
        ("deflate", _raw_deflate, True),
        ("gzip, deflate", lambda b: zlib.compress(gzip.compress(b)), True),
        ("br", lambda b: b"\x8b\x03\x80" + b + b"\x03", False),  # no brotli decoder: a counted gap
    ],
)
def test_compressed_request_forwarded_as_sent_and_observed(
    tmp_path: Path, encoding: str, encode: Any, scanned: bool
) -> None:
    st = Stack(tmp_path)
    sent = encode(body(f"my NRIC is {NRIC}"))

    async def go() -> None:
        async with st.run() as c:
            r = await c.post("/v1/messages", data=sent, headers={"Content-Encoding": encoding})
            assert r.status == 200
            headers, got = st.seen[-1]
            assert got == sent and headers["Content-Encoding"] == encoding

    run(go())
    (rec,) = st.observed()
    assert rec["scanned"] is scanned
    if scanned:
        assert [n["t"] for n in rec["new"]] == ["NRIC"]
    else:
        assert rec["reason"] == "unsupported_encoding"


def test_decode_is_bounded_and_rejects_damaged_streams() -> None:
    doc = b'{"messages":[]}'
    two_members = gzip.compress(doc[:5]) + gzip.compress(doc[5:])
    assert decode(two_members, "gzip", 1 << 20) == (doc, None)
    assert decode(doc, None, 10) == (doc, None)  # no coding: the cap is the listener's, not this one
    assert decode(doc, "identity", 1 << 20) == (doc, None)
    assert decode(gzip.compress(doc)[:-6], "gzip", 1 << 20) == (None, "undecodable_body")
    assert decode(gzip.compress(doc) + b"junk", "gzip", 1 << 20) == (None, "undecodable_body")
    assert decode(zlib.compress(doc) + b"junk", "deflate", 1 << 20) == (None, "undecodable_body")
    assert decode(doc, "zstd", 1 << 20) == (None, "unsupported_encoding")
    bomb = gzip.compress(bytes(200 << 20))
    tracemalloc.start()
    try:
        assert decode(bomb, "gzip", 4 << 20) == (None, "decoded_too_large")
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 16 << 20  # decoding stopped near the 4 MiB cap, not at 200 MiB


# --- F-05: invariant 1 under fuzzing ----------------------------------------------------------------


def _mutate(rng: random.Random, data: bytes) -> bytes:
    b = bytearray(data)
    for _ in range(rng.randint(1, 5)):
        i = rng.randrange(len(b) + 1)
        op = rng.randrange(3)
        if op == 0 and i < len(b):
            b[i] = rng.choice(b"\x00\x01\x7f\r\n :\t\xff")
        elif op == 1:
            b[i:i] = rng.choice([b"\r\n", b"\x00", b"Transfer-Encoding: chunked\r\n", b" "])
        elif i < len(b):
            del b[i]
    return bytes(b)


def test_fuzzed_requests_never_put_a_planted_value_in_logs_or_responses(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    rng = random.Random(1016)  # noqa: S311 — reproducible fuzz, not secrecy
    planted = body(f"NRIC {NRIC}")
    base = (
        f"POST /v1/messages/{NRIC} HTTP/1.1\r\n{LOCAL}X-Note: {NRIC}\r\n"
        f"Content-Type: application/json\r\nContent-Length: {len(planted)}\r\n\r\n"
    ).encode() + planted
    st = Stack(tmp_path)
    replies: list[bytes] = []

    async def go() -> None:
        async with st.run() as c:
            assert c.port is not None
            for _ in range(10):
                cases = [_mutate(rng, base) for _ in range(20)]
                replies.extend(await asyncio.gather(*(raw(c.port, x) for x in cases)))

    run(go())
    assert any(b" 400 " in r for r in replies)  # the fuzz did reach the parser's error path
    assert not [r for r in replies if NRIC.encode() in r]
    assert NRIC not in caplog.text


def test_library_log_filter_drops_arguments_and_tracebacks() -> None:
    proxy.quiet_library_logs()
    logger = logging.getLogger("aiohttp.server")
    records: list[logging.LogRecord] = []

    class Grab(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    h = Grab()
    logger.addHandler(h)
    try:
        try:
            raise ValueError(f"bad header {NRIC}")
        except ValueError:
            logger.exception("Error handling request %r", f"X-Note: {NRIC}")
    finally:
        logger.removeHandler(h)
    text = logging.Formatter().format(records[0])
    assert NRIC not in text and "ValueError" in text


# --- F-06: every request is a record or a counted gap ------------------------------------------------


def test_identifiers_in_path_query_and_model_are_observed_not_recorded(tmp_path: Path) -> None:
    st = Stack(tmp_path)

    async def go() -> None:
        async with st.run() as c:
            await c.post(f"/v1/messages?ref={NRIC}", data=body("hello", model=f"m-{NRIC}"))
            await c.get(f"/v1/files/{NRIC}")
            await c.post("/v1/messages", data=body("hello", model="m" * (MAX_MODEL + 1)))

    run(go())
    a, b, long_model = st.observed()
    assert a["model"] == f"<withheld:{len(NRIC) + 2}>" and a["path"] == "/v1/messages"
    assert [n["t"] for n in a["new"]] == ["NRIC"]  # query and model hold the same value: one digest
    assert b["path"] == f"<withheld:{len(NRIC) + 10}>" and b["reason"] == "no_body"
    assert [n["t"] for n in b["new"]] == ["NRIC"]
    assert long_model["model"] == f"<withheld:{MAX_MODEL + 1}>"
    assert NRIC not in json.dumps(st.records())


def test_unwritable_audit_is_counted_and_reported_by_the_next_record(tmp_path: Path) -> None:
    st = Stack(tmp_path)

    async def go() -> None:
        async with st.run() as c:
            original = st.observer.log.append
            st.observer.log.append = lambda r: (_ for _ in ()).throw(PermissionError("audit"))  # type: ignore[method-assign]
            assert (await c.post("/v1/messages", data=body("one"))).status == 200
            await asyncio.sleep(0.2)
            st.observer.log.append = original  # type: ignore[method-assign]
            assert (await c.post("/v1/messages", data=body("two"))).status == 200

    run(go())
    obs = st.observed()
    assert len(obs) == 1 and obs[0]["failed_before"] == 1
    stop = [r for r in st.records() if r["event"] == "observe_stop"]
    assert stop == [stop[0]] and stop[0]["failed"] == 0 and stop[0]["observed"] == 1


def test_carried_counts_appear_once_across_parts(tmp_path: Path) -> None:
    m, u = AuditKeyPair.generate(), AuditKeyPair.generate()
    obs = Observer(AuditLog(tmp_path / "a.jsonl", m.public, u.public, "lab"))
    obs.dropped = 2
    emails = " ".join(f"user{i}@example.com" for i in range(PER_RECORD + 5))
    recs = obs.observe(Request("r", "POST", "/v1/messages", body(emails), None, "cloud"))
    assert len(recs) == 2
    assert recs[0]["dropped_before"] == 2 and "dropped_before" not in recs[1]


def test_scan_failure_becomes_a_gap_record(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    m, u = AuditKeyPair.generate(), AuditKeyPair.generate()
    obs = Observer(AuditLog(tmp_path / "a.jsonl", m.public, u.public, "lab"))

    def boom(_: str) -> None:
        raise RuntimeError(f"detector crashed on {NRIC}")

    monkeypatch.setattr(obs, "_scan_block", boom)
    (rec,) = obs.observe(Request("r", "POST", "/v1/messages", body("x"), None, "cloud"))
    assert rec["scanned"] is False and rec["reason"] == "observer_error:RuntimeError"
    assert obs.health()["gaps"] == 1


# --- F-08: listener Host / Origin ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "host",
    ["127.0.0.1", "127.0.0.1:8787", "localhost", "LOCALHOST:1", "[::1]", "[::1]:8787", "127.0.0.2:80"],
)
def test_loopback_host_values_accepted(host: str) -> None:
    assert proxy._host_allowed(host)


@pytest.mark.parametrize(
    "host",
    [
        None,
        "",
        "evil.example",
        "evil.example:8787",
        "localhost.",
        "127.0.0.1.nip.io",
        "localhost.evil.example",
        "::1",
        "[::1",
        "[::1]x",
        "[127.0.0.1]",
        "127.0.0.1:",
        "127.0.0.1:abc",
        "127.0.0.1:8787:1",
        "127.0.0.1:1234567",
        "0.0.0.0",  # noqa: S104 — asserting it is refused
        "[fe80::1]",
        "192.168.1.5",
    ],
)
def test_other_host_values_refused(host: str | None) -> None:
    assert not proxy._host_allowed(host)


def test_listener_refusals_reach_neither_upstream_nor_audit(tmp_path: Path) -> None:
    st = Stack(tmp_path)

    async def go() -> None:
        async with st.run(allowed_origins=("http://localhost:3000",)) as c:
            assert c.port is not None
            no_host = await raw(c.port, b"GET /v1/models HTTP/1.0\r\n\r\n")
            assert no_host.startswith(b"HTTP/1.0 421") or no_host.startswith(b"HTTP/1.1 421")
            r = await c.get("/v1/models", headers={"Origin": "http://evil.example"})
            assert r.status == 403 and "ref " in await r.text()
            r = await c.get("/v1/models", headers={"Origin": "null"})
            assert r.status == 403
            assert st.seen == []
            r = await c.get("/v1/models", headers={"Origin": "http://localhost:3000"})
            assert r.status == 200 and len(st.seen) == 1

    run(go())
    assert len(st.observed()) == 1


def test_decode_cap_follows_the_listener_body_limit(tmp_path: Path) -> None:
    st = Stack(tmp_path)
    sent = gzip.compress(body("x" * (3 << 20)))  # ~3 MiB decoded, a few KiB on the wire

    async def go() -> None:
        async with st.run(max_body=1 << 20) as c:
            r = await c.post("/v1/messages", data=sent, headers={"Content-Encoding": "gzip"})
            assert r.status == 200

    run(go())
    assert [r["reason"] for r in st.observed()] == ["decoded_too_large"]


def test_counts_carried_by_an_unwritten_record_are_kept(tmp_path: Path) -> None:
    m, u = AuditKeyPair.generate(), AuditKeyPair.generate()
    obs = Observer(AuditLog(tmp_path / "a.jsonl", m.public, u.public, "lab"))
    obs.dropped = 2
    original = obs.log.append

    def refuse(record: dict[str, Any]) -> dict[str, Any]:
        raise PermissionError("audit")

    obs.log.append = refuse  # type: ignore[method-assign]
    with pytest.raises(PermissionError):
        obs.observe(Request("r1", "POST", "/v1/messages", body("one"), None, "cloud"))
    obs.log.append = original  # type: ignore[method-assign]
    (rec,) = obs.observe(Request("r2", "POST", "/v1/messages", body("two"), None, "cloud"))
    assert rec["dropped_before"] == 2

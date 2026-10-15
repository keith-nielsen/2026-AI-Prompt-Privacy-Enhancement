"""Phase 2a proxy under hostile or broken input: framing, targets, disconnects, timeouts, limits,
concurrency, fuzzing. The property that matters for a proxy: whatever the client sends, the upstream
sees only cleanly re-framed requests (own Content-Length, no client Transfer-Encoding), so client and
upstream can never disagree about where a request ends. Fake upstream on loopback only."""

from __future__ import annotations

import asyncio
import hashlib
import json
import random
from collections.abc import AsyncIterator, Coroutine
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest
from aiohttp import ClientPayloadError, ServerDisconnectedError, web
from aiohttp.test_utils import TestClient, TestServer
from hypothesis import given, settings
from hypothesis import strategies as st

from prompt_privacy.audit.keys import AuditKeyPair
from prompt_privacy.audit.log import AuditLog
from prompt_privacy.proxy import app as proxy
from prompt_privacy.proxy.observe import Observer, Request, extract

H = "Host: x\r\n"


def run(coro: Coroutine[Any, Any, None]) -> None:
    asyncio.run(coro)


class Upstream:
    def __init__(self) -> None:
        self.seen: list[tuple[str, str, Any, bytes]] = []
        self.stopped = asyncio.Event()  # an endless stream noticed its client went away
        self.app = web.Application(client_max_size=1 << 30)
        self.app.router.add_route("*", "/{tail:.*}", self.handle)

    async def handle(self, request: web.Request) -> web.StreamResponse:
        body = await request.read()
        self.seen.append((request.method, request.raw_path, request.headers.copy(), body))
        p = request.path
        if p == "/endless":
            resp = web.StreamResponse()
            await resp.prepare(request)
            try:
                while True:
                    await resp.write(b"data: tick\n\n")
                    await asyncio.sleep(0.01)
            finally:  # cancelled (or a write fails) once the proxy drops the upstream connection
                self.stopped.set()
        if p == "/die-mid-stream":
            resp = web.StreamResponse(headers={"Content-Length": "1000"})
            await resp.prepare(request)
            await resp.write(b"x" * 10)
            assert request.transport is not None
            request.transport.abort()
            return resp
        if p == "/stall-before-headers":
            await asyncio.sleep(10)
        if p == "/stall-mid-body":
            resp = web.StreamResponse()
            await resp.prepare(request)
            await resp.write(b"first")
            await asyncio.sleep(10)
        if p.startswith("/stream/"):
            ident = p.rsplit("/", 1)[1].encode()
            resp = web.StreamResponse()
            await resp.prepare(request)
            for i in range(20):
                await resp.write(ident + b":" + str(i).encode() + b"\n")
                await asyncio.sleep(random.random() / 200)  # noqa: S311 — jitter, not secrecy
            await resp.write_eof()
            return resp
        if p == "/multi":
            resp = web.Response(body=b"ok")
            resp.headers.add("Set-Cookie", "a=1")
            resp.headers.add("Set-Cookie", "b=2")
            return resp
        return web.Response(body=hashlib.sha256(body).hexdigest().encode())


@asynccontextmanager
async def stack(tmp_path: Path, **kw: Any) -> AsyncIterator[tuple[TestClient, Upstream, int]]:
    up = Upstream()
    up_server = TestServer(up.app, host="127.0.0.1")
    await up_server.start_server()
    m, t = AuditKeyPair.generate(), AuditKeyPair.generate()
    observer = Observer(AuditLog(tmp_path / "audit.jsonl", m.public, t.public, "lab"))
    app = proxy.build_app(proxy.Settings(upstream=str(up_server.make_url("/")).rstrip("/"), **kw), observer)
    client = TestClient(TestServer(app, host="127.0.0.1"))
    await client.start_server()
    try:
        assert client.port is not None
        yield client, up, client.port
    finally:
        await client.close()
        await up_server.close()


async def raw_exchange(port: int, payload: bytes, quiet: float = 0.5) -> bytes:
    """Send raw bytes, collect everything until the connection is quiet or closed."""
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(payload)
    await w.drain()
    data = b""
    while True:
        try:
            chunk = await asyncio.wait_for(r.read(65536), quiet)
        except TimeoutError:
            break
        if not chunk:
            break
        data += chunk
    w.close()
    await asyncio.sleep(0.05)
    return data


def statuses(data: bytes) -> list[int]:
    return [
        int(data[i + 9 : i + 12])
        for i in range(len(data))
        if data[i : i + 7] == b"HTTP/1." and data[i + 8 : i + 9] == b" "
    ]


def assert_clean_framing(up: Upstream) -> None:
    for _, _, headers, body in up.seen:
        assert "Transfer-Encoding" not in headers
        assert int(headers.get("Content-Length", "0")) == len(body)
        assert "Upgrade" not in headers


# --- framing (RFC 9112 §6) ---------------------------------------------------------------------

REJECTED = {
    "cl_and_te": f"POST /v1/messages HTTP/1.1\r\n{H}Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n"
    f"0\r\n\r\nGET /smuggled HTTP/1.1\r\n{H}\r\n",
    "dup_cl_differ": f"POST /a HTTP/1.1\r\n{H}Content-Length: 3\r\nContent-Length: 30\r\n\r\nabc",
    "dup_cl_same": f"POST /a HTTP/1.1\r\n{H}Content-Length: 3\r\nContent-Length: 3\r\n\r\nabc",
    "cl_list": f"POST /a HTTP/1.1\r\n{H}Content-Length: 3, 3\r\n\r\nabc",
    "cl_plus": f"POST /a HTTP/1.1\r\n{H}Content-Length: +3\r\n\r\nabc",
    "cl_negative": f"POST /a HTTP/1.1\r\n{H}Content-Length: -1\r\n\r\n",
    "cl_space_in_name": f"POST /a HTTP/1.1\r\n{H}Content-Length : 3\r\n\r\nabc",
    "te_unknown": f"POST /a HTTP/1.1\r\n{H}Transfer-Encoding: xchunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
    "te_chunked_not_last": f"POST /a HTTP/1.1\r\n{H}Transfer-Encoding: chunked, gzip\r\n\r\n"
    "3\r\nabc\r\n0\r\n\r\n",
    "te_duplicate": f"POST /a HTTP/1.1\r\n{H}Transfer-Encoding: chunked\r\n"
    "Transfer-Encoding: identity\r\n\r\n"
    "3\r\nabc\r\n0\r\n\r\n",
    "chunk_size_junk": f"POST /a HTTP/1.1\r\n{H}Transfer-Encoding: chunked\r\n\r\n3x\r\nabc\r\n0\r\n\r\n",
    "chunk_size_overflow": f"POST /a HTTP/1.1\r\n{H}Transfer-Encoding: chunked\r\n\r\n"
    "FFFFFFFFFFFFFFFFF\r\nabc\r\n0\r\n\r\n",
    "chunk_bare_lf": f"POST /a HTTP/1.1\r\n{H}Transfer-Encoding: chunked\r\n\r\n3\nabc\n0\n\n",
    "obs_fold": f"POST /a HTTP/1.1\r\n{H}X-A: 1\r\n  folded\r\nContent-Length: 3\r\n\r\nabc",
    "header_bare_lf": "POST /a HTTP/1.1\nHost: x\nContent-Length: 3\n\nabc",
    "header_bare_cr": f"POST /a HTTP/1.1\r\n{H}X-A: 1\rX-B: 2\r\nContent-Length: 3\r\n\r\nabc",
    "header_nul": f"GET /a HTTP/1.1\r\n{H}X-A: a\x00b\r\n\r\n",
    "space_before_colon": f"GET /a HTTP/1.1\r\n{H}X-A : 1\r\n\r\n",
    "no_host": "GET /a HTTP/1.1\r\n\r\n",
    "two_hosts": f"GET /a HTTP/1.1\r\n{H}Host: y\r\n\r\n",
    "header_too_long": f"GET /a HTTP/1.1\r\n{H}X-Big: {'a' * 20000}\r\n\r\n",
    "too_many_headers": f"GET /a HTTP/1.1\r\n{H}" + "".join(f"X-{i}: 1\r\n" for i in range(500)) + "\r\n",
    "http2_preface": "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
    "control_in_method": f"G\x01T /a HTTP/1.1\r\n{H}\r\n",
    # request targets the proxy itself refuses
    "absolute_form": f"GET http://evil.invalid/a HTTP/1.1\r\n{H}\r\n",
    "dot_segments": f"GET /../../etc/passwd HTTP/1.1\r\n{H}\r\n",
    "encoded_dot_segments": f"GET /v1/%2e%2e/x HTTP/1.1\r\n{H}\r\n",
}

REFRAMED = {
    "te_tab": f"POST /a HTTP/1.1\r\n{H}Transfer-Encoding:\tchunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
    "te_on_http10": f"POST /a HTTP/1.0\r\n{H}Transfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
    "chunked": f"POST /a HTTP/1.1\r\n{H}Transfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
    "chunk_extension": f"POST /a HTTP/1.1\r\n{H}Transfer-Encoding: chunked\r\n\r\n3;x=y\r\nabc\r\n0\r\n\r\n",
    "trailer_then_pipelined": f"POST /a HTTP/1.1\r\n{H}Transfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n"
    f"X-T: 1\r\n\r\nGET /next HTTP/1.1\r\n{H}\r\n",
    "pipelined": f"GET /a HTTP/1.1\r\n{H}\r\nGET /b HTTP/1.1\r\n{H}\r\n",
    "expect_continue": f"POST /a HTTP/1.1\r\n{H}Expect: 100-continue\r\nContent-Length: 3\r\n\r\nabc",
    "upgrade_websocket": f"GET /a HTTP/1.1\r\n{H}Connection: Upgrade\r\nUpgrade: websocket\r\n"
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
    "upgrade_h2c": f"GET /a HTTP/1.1\r\n{H}Connection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\n"
    "HTTP2-Settings: AAMAAABkAAQCAAAAAAIAAAAA\r\n\r\n",
}


@pytest.mark.parametrize("name", sorted(REJECTED))
def test_ambiguous_or_refused_requests_never_reach_upstream(name: str, tmp_path: Path) -> None:
    async def go() -> None:
        async with stack(tmp_path) as (_, up, port):
            data = await raw_exchange(port, REJECTED[name].encode("latin-1"))
            assert statuses(data)[:1] == [400], data[:200]
            assert up.seen == []

    run(go())


@pytest.mark.parametrize("name", sorted(REFRAMED))
def test_accepted_requests_are_reframed_cleanly(name: str, tmp_path: Path) -> None:
    async def go() -> None:
        async with stack(tmp_path) as (_, up, port):
            data = await raw_exchange(port, REFRAMED[name].encode("latin-1"))
            assert statuses(data) and all(s in (100, 200) for s in statuses(data))
            assert up.seen
            assert_clean_framing(up)
            assert all(path.startswith("/") for _, path, _, _ in up.seen)

    run(go())


def test_connect_is_not_tunnelled(tmp_path: Path) -> None:
    async def go() -> None:
        async with stack(tmp_path) as (_, up, port):
            data = await raw_exchange(port, f"CONNECT evil.invalid:443 HTTP/1.1\r\n{H}\r\n".encode())
            assert statuses(data) and statuses(data)[0] in (400, 404, 405)
            assert up.seen == []

    run(go())


# --- disconnects and timeouts ------------------------------------------------------------------


def test_client_disconnect_mid_stream_stops_upstream(tmp_path: Path) -> None:
    async def go() -> None:
        async with stack(tmp_path) as (client, up, _):
            r = await client.get("/endless")
            await r.content.readany()
            r.close()  # client walks away mid-stream
            await asyncio.wait_for(up.stopped.wait(), 5)
            assert (await client.post("/after", data=b"x")).status == 200  # proxy still healthy

    run(go())


def test_upstream_dying_mid_stream_fails_the_client_promptly(tmp_path: Path) -> None:
    async def go() -> None:
        async with stack(tmp_path) as (client, _, _):
            r = await client.get("/die-mid-stream")
            with pytest.raises((ClientPayloadError, ServerDisconnectedError)):
                await asyncio.wait_for(r.read(), 5)
            assert (await client.post("/after", data=b"x")).status == 200

    run(go())


def test_upstream_stall_before_headers_gives_502(tmp_path: Path) -> None:
    async def go() -> None:
        async with stack(tmp_path, read_timeout=0.3) as (client, _, _):
            r = await asyncio.wait_for(client.get("/stall-before-headers"), 5)
            assert r.status == 502 and "ref " in (await r.json())["error"]["message"]

    run(go())


def test_upstream_stall_mid_body_fails_the_client_within_timeout(tmp_path: Path) -> None:
    async def go() -> None:
        async with stack(tmp_path, read_timeout=0.3) as (client, _, _):
            r = await client.get("/stall-mid-body")
            assert r.status == 200
            with pytest.raises((ClientPayloadError, ServerDisconnectedError)):
                await asyncio.wait_for(r.read(), 5)

    run(go())


# --- size limits, concurrency, headers ---------------------------------------------------------


def test_large_body_is_forwarded_intact(tmp_path: Path) -> None:
    body = random.Random(1).randbytes(8 * 1024 * 1024)  # noqa: S311 — test data, not secrecy

    async def go() -> None:
        async with stack(tmp_path) as (client, up, _):
            r = await client.post("/blob", data=body)
            assert (await r.read()).decode() == hashlib.sha256(body).hexdigest()
            assert_clean_framing(up)

    run(go())


def test_body_over_limit_is_refused_and_not_forwarded(tmp_path: Path) -> None:
    async def go() -> None:
        async with stack(tmp_path, max_body=1024 * 1024) as (client, up, _):
            r = await client.post("/blob", data=b"x" * (1024 * 1024 + 1))
            assert r.status == 413
            assert up.seen == []

    run(go())


def test_concurrent_streams_do_not_cross(tmp_path: Path) -> None:
    async def one(client: TestClient, i: int) -> None:
        r = await client.get(f"/stream/s{i}")
        lines = (await r.read()).decode().splitlines()
        assert lines == [f"s{i}:{n}" for n in range(20)]

    async def go() -> None:
        async with stack(tmp_path) as (client, _, _):
            await asyncio.gather(*(one(client, i) for i in range(50)))

    run(go())


def test_duplicate_headers_keep_every_value_in_order(tmp_path: Path) -> None:
    async def go() -> None:
        async with stack(tmp_path) as (client, up, _):
            r = await client.get("/multi", headers=[("anthropic-beta", "a"), ("anthropic-beta", "b")])
            assert r.headers.getall("Set-Cookie") == ["a=1", "b=2"]
            assert up.seen[0][2].getall("anthropic-beta") == ["a", "b"]

    run(go())


# --- fuzzing -----------------------------------------------------------------------------------

_BASE = (
    b"POST /v1/messages HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Type: application/json\r\n"
    b"Content-Length: 45\r\n\r\n"
    b'{"messages":[{"role":"user","content":"hi"}]}'
)


def _mutate(rng: random.Random, data: bytes) -> bytes:
    b = bytearray(data)
    for _ in range(rng.randint(1, 6)):
        op, i = rng.randrange(4), rng.randrange(len(b) + 1)
        if op == 0 and i < len(b):
            b[i] = rng.randrange(256)
        elif op == 1:
            b[i:i] = bytes([rng.choice(b"\r\n :\t,;\x00-0123456789abcdefABCDEF")])
        elif op == 2 and i < len(b):
            del b[i]
        else:
            b[i:i] = rng.choice(
                [b"\r\n", b"Transfer-Encoding: chunked\r\n", b"Content-Length: 0\r\n", b"0\r\n\r\n"]
            )
    return bytes(b)


def test_mutation_fuzz_keeps_framing_clean_and_proxy_alive(tmp_path: Path) -> None:
    rng = random.Random(20261016)  # noqa: S311 — reproducible fuzz, not secrecy

    async def go() -> None:
        async with stack(tmp_path) as (client, up, port):
            cases = [_mutate(rng, _BASE) for _ in range(300)]
            for i in range(0, len(cases), 25):  # independent connections, 25 at a time
                results = await asyncio.gather(
                    *(raw_exchange(port, c, quiet=0.15) for c in cases[i : i + 25])
                )
                for data in results:
                    assert all(s < 500 or s == 502 for s in statuses(data)), data[:200]
            assert_clean_framing(up)
            assert (await client.post("/after", data=b"x")).status == 200

    run(go())


_json = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | st.text(),
    lambda kids: st.lists(kids, max_size=5) | st.dictionaries(st.text(max_size=8), kids, max_size=5),
    max_leaves=40,
)
_messages_like = st.fixed_dictionaries(
    {
        "messages": st.lists(
            st.fixed_dictionaries({"role": st.sampled_from(["user", "assistant", 3]), "content": _json})
        )
    },
    optional={"system": _json, "model": _json},
)


@settings(max_examples=300, deadline=None)
@given(st.one_of(_json, _messages_like))
def test_extract_never_raises_on_arbitrary_json(doc: Any) -> None:
    texts, _, reason = extract("/v1/messages", json.dumps(doc).encode())
    assert reason is None or reason == "unparsable_body"
    assert all(isinstance(t, str) for t in texts.texts)


def test_observe_never_raises_on_arbitrary_bytes(tmp_path: Path) -> None:
    m, t = AuditKeyPair.generate(), AuditKeyPair.generate()
    observer = Observer(AuditLog(tmp_path / "audit.jsonl", m.public, t.public, "lab"))
    rng = random.Random(7)  # noqa: S311 — reproducible fuzz, not secrecy
    samples = [rng.randbytes(rng.randrange(512)) for _ in range(200)]
    samples += [
        _mutate(rng, b'{"messages":[{"role":"user","content":[{"type":"text","text":"S1234567D"}]}]}')
        for _ in range(200)
    ]
    for body in samples:
        observer.observe(Request("r", "POST", "/v1/messages", body, None, "cloud"))

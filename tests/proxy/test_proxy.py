"""Phase 2a proxy: pass-through is byte-exact, streaming is not buffered, observation is sealed and
never affects traffic. Every test runs a fake upstream on loopback; nothing leaves the host."""

from __future__ import annotations

import asyncio
import gzip
import json
from collections.abc import AsyncIterator, Callable, Coroutine
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from prompt_privacy.audit.keys import AuditKeyPair
from prompt_privacy.audit.log import AuditLog, open_log, verify_chain
from prompt_privacy.proxy import app as proxy
from prompt_privacy.proxy.observe import PER_RECORD, Observer
from tests.proxy.support import ProxyTestServer

NRIC, EMAIL = "S1234567D", "tan.wei.ming@example.com"  # synthetic
SSE = [
    b'event: message_start\ndata: {"type":"mess',
    b'age_start"}\n\n',
    b'event: content_block_delta\ndata: {"text":"caf\xc3',  # split inside a UTF-8 character
    b'\xa9"}\n\n',
    b"event: message_stop\ndata: {}\n\n",
]


def run(coro: Coroutine[Any, Any, None]) -> None:
    asyncio.run(coro)


class Upstream:
    def __init__(self) -> None:
        self.seen: list[dict[str, Any]] = []
        self.gate = asyncio.Event()
        self.app = web.Application()
        self.app.router.add_route("*", "/{tail:.*}", self.handle)

    async def handle(self, request: web.Request) -> web.StreamResponse:
        body = await request.read()
        self.seen.append(
            {
                "method": request.method,
                "path_qs": request.path_qs,
                "headers": request.headers.copy(),
                "body": body,
            }
        )
        if request.path == "/v1/messages" and b'"stream":true' in body:
            resp = web.StreamResponse(headers={"Content-Type": "text/event-stream", "request-id": "req_up_1"})
            await resp.prepare(request)
            await resp.write(SSE[0])
            await asyncio.wait_for(self.gate.wait(), 5)  # held until the client has seen chunk 1
            for chunk in SSE[1:]:
                await resp.write(chunk)
                await asyncio.sleep(0)
            await resp.write_eof()
            return resp
        if request.path == "/gzip":
            return web.Response(body=gzip.compress(b"x" * 1000), headers={"Content-Encoding": "gzip"})
        if request.path == "/limited":
            return web.Response(status=429, body=b'{"type":"error"}', headers={"retry-after": "7"})
        if request.path == "/redirect":
            return web.Response(status=302, headers={"Location": "https://elsewhere.invalid/"})
        if request.path == "/hop":
            return web.Response(body=b"ok", headers={"Connection": "x-hop", "X-Hop": "1", "X-End": "2"})
        return web.Response(
            body=b'{"id":"msg_1","echo":' + body + b"}" if body else b"{}", headers={"request-id": "r1"}
        )


@asynccontextmanager
async def stack(tmp_path: Path, **settings: Any) -> AsyncIterator[tuple[TestClient, Upstream, Observer]]:
    up = Upstream()
    up_server = TestServer(up.app, host="127.0.0.1")
    await up_server.start_server()
    m, t = AuditKeyPair.generate(), AuditKeyPair.generate()
    observer = Observer(AuditLog(tmp_path / "audit.jsonl", m.public, t.public, "lab"))
    app = proxy.build_app(
        proxy.Settings(upstream=str(up_server.make_url("/")).rstrip("/"), **settings), observer
    )
    client = TestClient(ProxyTestServer(app, host="127.0.0.1"))
    await client.start_server()
    (tmp_path / "keys").mkdir()
    stack.keys = (m, t)  # type: ignore[attr-defined]
    try:
        yield client, up, observer
    finally:
        await client.close()  # app cleanup drains the observation worker
        await up_server.close()


def records(tmp_path: Path) -> list[dict[str, Any]]:
    m, t = stack.keys  # type: ignore[attr-defined]
    assert verify_chain(tmp_path / "audit.jsonl").ok
    return list(open_log(tmp_path / "audit.jsonl", m, t))


def messages_body(*user_texts: str, stream: bool = False) -> bytes:
    msgs: list[dict[str, Any]] = []
    for i, text in enumerate(user_texts):
        if i:
            msgs.append({"role": "assistant", "content": [{"type": "text", "text": f"Noted {NRIC}."}]})
        msgs.append({"role": "user", "content": text})
    doc = {"model": "claude-test", "max_tokens": 16, "stream": stream, "messages": msgs}
    return json.dumps(doc, separators=(",", ":")).encode()


# --- pass-through ------------------------------------------------------------------------------


def test_request_and_response_are_byte_exact(tmp_path: Path) -> None:
    async def go() -> None:
        async with stack(tmp_path) as (client, up, _):
            body = b'{"model":"m",  "messages":[{"role":"user","content":"hi \\u00e9"}]}'
            r = await client.post(
                "/v1/messages?beta=true",
                data=body,
                headers={
                    "x-api-key": "test-key",
                    "anthropic-version": "2023-06-01",
                    "anthropic-beta": "a,b",
                    "content-type": "application/json",
                    "x-claude-code-session-id": "sess-1",
                    "Connection": "keep-alive, x-drop-me",
                    "x-drop-me": "1",
                },
                skip_auto_headers=("User-Agent", "Accept", "Accept-Encoding"),
            )
            assert r.status == 200 and await r.read() == b'{"id":"msg_1","echo":' + body + b"}"
            assert r.headers["request-id"] == "r1"
            seen = up.seen[0]
            assert seen["path_qs"] == "/v1/messages?beta=true" and seen["body"] == body
            h = seen["headers"]
            assert h["x-api-key"] == "test-key" and h["anthropic-beta"] == "a,b"
            assert h["x-claude-code-session-id"] == "sess-1" and h["content-type"] == "application/json"
            assert "x-drop-me" not in h and h["Host"] != client.host
            assert "User-Agent" not in h  # the proxy adds no client headers of its own

    run(go())


def test_sse_is_relayed_as_it_arrives_and_byte_exact(tmp_path: Path) -> None:
    async def go() -> None:
        async with stack(tmp_path) as (client, up, _):
            r = await client.post("/v1/messages", data=messages_body("hello", stream=True))
            assert r.headers["Content-Type"] == "text/event-stream" and r.headers["request-id"] == "req_up_1"
            first = await asyncio.wait_for(r.content.readany(), 5)  # would time out if buffered
            assert SSE[0].startswith(first) and first
            up.gate.set()
            rest = await r.read()
            assert first + rest == b"".join(SSE)

    run(go())


def test_compressed_body_passes_compressed(tmp_path: Path) -> None:
    async def go() -> None:
        async with stack(tmp_path) as (client, _, _):
            r = await client.get("/gzip", auto_decompress=False)
            assert r.headers["Content-Encoding"] == "gzip"
            assert gzip.decompress(await r.read()) == b"x" * 1000

    run(go())


def test_status_redirect_and_hop_headers(tmp_path: Path) -> None:
    async def go() -> None:
        async with stack(tmp_path) as (client, _, _):
            r = await client.get("/limited")
            assert (
                r.status == 429 and r.headers["retry-after"] == "7" and await r.read() == b'{"type":"error"}'
            )
            r = await client.get("/redirect", allow_redirects=False)
            assert r.status == 302 and r.headers["Location"] == "https://elsewhere.invalid/"
            r = await client.get("/hop")
            assert r.headers["X-End"] == "2" and "X-Hop" not in r.headers

    run(go())


def test_unreachable_upstream_gives_opaque_anthropic_error(tmp_path: Path) -> None:
    async def go() -> None:
        m, t = AuditKeyPair.generate(), AuditKeyPair.generate()
        observer = Observer(AuditLog(tmp_path / "audit.jsonl", m.public, t.public, "lab"))
        app = proxy.build_app(proxy.Settings(upstream="http://127.0.0.1:9", connect_timeout=2), observer)
        async with TestClient(ProxyTestServer(app, host="127.0.0.1")) as client:
            r = await client.post("/v1/messages", data=messages_body(f"my NRIC is {NRIC}"))
            assert r.status == 502
            err = await r.json()
            assert err["type"] == "error" and err["error"]["type"] == "api_error"
            assert "ref " in err["error"]["message"] and NRIC not in json.dumps(err)

    run(go())


# --- observation -------------------------------------------------------------------------------


def test_findings_are_sealed_digested_and_deduplicated_per_conversation(tmp_path: Path) -> None:
    async def go() -> None:
        async with stack(tmp_path) as (client, _, _):
            hdr = {"x-claude-code-session-id": "sess-A"}
            first = f"my NRIC is {NRIC}, email {EMAIL}"
            await client.post("/v1/messages", data=messages_body(first), headers=hdr)
            await client.post("/v1/messages", data=messages_body(first, "and again"), headers=hdr)
            await client.post(
                "/v1/messages", data=messages_body(first), headers={"x-claude-code-session-id": "B"}
            )

    run(go())
    raw = (tmp_path / "audit.jsonl").read_text()
    assert NRIC not in raw and EMAIL not in raw and "sess-A" not in raw
    recs = records(tmp_path)
    assert recs[0]["event"] == "digest_key"
    obs = [r for r in recs if r["event"] == "observe"]
    assert [r["findings_total"] for r in obs] == [2, 2, 2]  # assistant turn (NRIC echo) not scanned
    assert [len(r["new"]) for r in obs] == [2, 0, 2]
    assert {n["t"] for n in obs[0]["new"]} == {"NRIC", "EMAIL"}
    assert obs[0]["conv"] == obs[1]["conv"] != obs[2]["conv"]
    assert obs[0]["new"] == obs[2]["new"]  # same value, same digest, across conversations
    assert all(r["flow"] == "prompt" and r["zone"] == "loopback" and r["scanned"] for r in obs)
    assert NRIC not in json.dumps(recs) and EMAIL not in json.dumps(recs)


def test_many_findings_split_into_parts(tmp_path: Path) -> None:
    emails = " ".join(f"user{i}@example.com" for i in range(PER_RECORD + 5))

    async def go() -> None:
        async with stack(tmp_path) as (client, _, _):
            await client.post("/v1/messages", data=messages_body(emails))

    run(go())
    obs = [r for r in records(tmp_path) if r["event"] == "observe"]
    assert [(r["part"], r["parts"], len(r["new"])) for r in obs] == [(0, 2, PER_RECORD), (1, 2, 5)]


def test_unparsed_requests_are_recorded_as_coverage_gaps(tmp_path: Path) -> None:
    async def go() -> None:
        async with stack(tmp_path) as (client, _, _):
            await client.get("/v1/models")
            await client.post("/v1/messages", data=b"{not json")
            await client.post("/v1/other", data=b"{}")

    run(go())
    obs = [r for r in records(tmp_path) if r["event"] == "observe"]
    assert [(r["scanned"], r["reason"]) for r in obs] == [
        (False, "no_body"),
        (False, "unparsable_body"),
        (False, "unsupported_path"),
    ]


def test_observation_failure_or_backlog_never_affects_traffic(tmp_path: Path) -> None:
    async def go() -> None:
        async with stack(tmp_path, max_pending=0) as (client, _, observer):
            for _ in range(3):
                r = await client.post("/v1/messages", data=messages_body(NRIC))
                assert r.status == 200

    run(go())
    stop = [r for r in records(tmp_path) if r["event"] == "observe_stop"]
    assert [(s["dropped"], s["observed"]) for s in stop] == [(3, 0)]  # drops survive shutdown (F-06)

    async def broken() -> None:
        async with stack(tmp_path / "b") as (client, _, observer):

            def boom(_: object) -> None:
                raise RuntimeError("detector crashed")

            observer.observe = boom  # type: ignore[method-assign,assignment]
            r = await client.post("/v1/messages", data=messages_body(NRIC))
            assert r.status == 200

    (tmp_path / "b").mkdir()
    run(broken())
    stop = [r for r in records(tmp_path / "b") if r["event"] == "observe_stop"]
    assert [s["failed"] for s in stop] == [1]


# --- invariants --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "host",
    [
        "0.0.0.0",  # noqa: S104 (asserting it is refused)
        "192.168.1.5",
        "::",
        "localhost",
        "example.com",
    ],
)
def test_listen_refuses_non_loopback(host: str) -> None:
    with pytest.raises(proxy.RefusedConfig):
        proxy.check_listen(host)


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "[::1]", "127.0.0.2"])
def test_listen_accepts_loopback(host: str) -> None:
    proxy.check_listen(host)


@pytest.mark.parametrize(
    ("upstream", "ok"),
    [
        ("https://api.anthropic.com", True),
        ("http://127.0.0.1:4000", True),
        ("http://api.anthropic.com", False),
        ("ftp://127.0.0.1", False),
        ("https://api.anthropic.com/?x=1", False),
    ],
)
def test_upstream_rules(upstream: str, ok: bool) -> None:
    check: Callable[[], None] = proxy.Settings(upstream=upstream).check
    if ok:
        check()
    else:
        with pytest.raises(proxy.RefusedConfig):
            check()


def test_pure_python_parser_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    from aiohttp import http_parser

    proxy.require_compiled_parser()
    monkeypatch.setattr(http_parser, "HttpRequestParser", http_parser.HttpRequestParserPy)
    with pytest.raises(proxy.RefusedConfig):
        proxy.require_compiled_parser()

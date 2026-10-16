"""Conformance: `ppe serve` (phase 2a) against README, ADR-0001/0007/0010 and invariant 1.

See tests/conformance/test_claims_engine.py for the C-nn / F-nn convention. Fake upstreams on loopback only;
nothing leaves the host. Synthetic data only.
"""

from __future__ import annotations

import asyncio
import datetime
import gzip
import hashlib
import hmac
import json
import logging
import socket
import ssl
import time
from collections.abc import AsyncIterator, Coroutine
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from prompt_privacy.audit.keys import AuditKeyPair
from prompt_privacy.audit.log import AuditLog, open_log
from prompt_privacy.cli.main import build_parser
from prompt_privacy.core.keys import lp
from prompt_privacy.core.normalise import norm
from prompt_privacy.core.types import EntityType
from prompt_privacy.proxy import app as proxy
from prompt_privacy.proxy.observe import Observer
from tests.proxy.support import ProxyTestServer

NRIC = "S1234567D"  # widely published sample value


def run(coro: Coroutine[Any, Any, None]) -> None:
    asyncio.run(coro)


def body(text: str, model: str = "claude-test") -> bytes:
    return json.dumps({"model": model, "messages": [{"role": "user", "content": text}]}).encode()


class Stack:
    """Fake upstream (raw bytes, no decompression) + proxy + sealed audit, all on loopback."""

    def __init__(self, tmp: Path, upstream: str | None = None, ssl_ctx: ssl.SSLContext | None = None) -> None:
        self.tmp, self.forced_upstream, self.ssl_ctx = tmp, upstream, ssl_ctx
        self.seen: list[tuple[Any, bytes]] = []
        self.m, self.u = AuditKeyPair.generate(), AuditKeyPair.generate()

    async def _h(self, r: web.Request) -> web.Response:
        self.seen.append((r.headers.copy(), await r.read()))
        return web.Response(body=b'{"ok":true}', content_type="application/json")

    @asynccontextmanager
    async def run(self, **settings: Any) -> AsyncIterator[TestClient]:
        upa = web.Application(client_max_size=1 << 30, handler_args={"auto_decompress": False})
        upa.router.add_route("*", "/{t:.*}", self._h)
        up = (
            TestServer(upa, host="127.0.0.1", ssl=self.ssl_ctx)
            if self.ssl_ctx
            else TestServer(upa, host="127.0.0.1")
        )
        await up.start_server()
        self.observer = Observer(AuditLog(self.tmp / "a.jsonl", self.m.public, self.u.public, "lab"))
        upstream = self.forced_upstream or str(up.make_url("/")).rstrip("/")
        if self.ssl_ctx:
            upstream = f"https://127.0.0.1:{up.port}"
        client = TestClient(
            ProxyTestServer(proxy.build_app(proxy.Settings(upstream=upstream, **settings), self.observer))
        )
        await client.start_server()
        try:
            yield client
        finally:
            await client.close()
            await up.close()

    def records(self) -> list[dict[str, Any]]:
        return list(open_log(self.tmp / "a.jsonl", self.m, self.u))


# --- forwarding -------------------------------------------------------------------------------------


def test_c34_compressed_request_body_forwarded_unchanged(tmp_path: Path) -> None:
    """C-34 (README: 'forwards traffic unchanged'; app docstring: 'body bytes in both directions')."""
    st = Stack(tmp_path)

    async def go() -> None:
        async with st.run() as c:
            gz = gzip.compress(body(f"NRIC {NRIC}"))
            await c.post("/v1/messages", data=gz, headers={"Content-Encoding": "gzip"})
            assert st.seen[-1][1] == gz

    run(go())


def test_c43_decompression_bomb_is_bounded(tmp_path: Path) -> None:
    """C-43 (threat model §5 D: 'size caps; bounded decoding'). The relay never decodes (C-34), so a gzip
    bomb is forwarded as sent; the observer's bounded copy stops at the cap and records a counted gap.
    A raw body over the cap is refused with 413 and nothing reaches the upstream.
    (Restated 2026-10-16: the original form, 413 for a small compressed body, required relay-side
    decoding and so contradicted C-34; see review F-04.)"""
    st = Stack(tmp_path)
    bomb = gzip.compress(bytes(100 << 20))

    async def go() -> None:
        async with st.run(max_body=8 << 20) as c:
            r = await c.post("/v1/messages", data=bomb, headers={"Content-Encoding": "gzip"})
            assert r.status == 200 and st.seen[-1][1] == bomb
            r = await c.post("/v1/messages", data=bytes((8 << 20) + 1))
            assert r.status == 413 and len(st.seen) == 1

    run(go())
    gaps = [r for r in st.records() if r["event"] == "observe" and not r["scanned"]]
    assert [g["reason"] for g in gaps] == ["decoded_too_large"]


def _self_signed() -> tuple[bytes, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))]),
            False,
        )
        .sign(key, hashes.SHA256())
    )
    pem_key = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    return cert.public_bytes(serialization.Encoding.PEM), pem_key


def test_c35_tls_to_upstream_is_verified(tmp_path: Path) -> None:
    """C-35 (threat model §5 cloud leg: 'TLS with system trust store'): an untrusted cert is refused."""
    cert, key = _self_signed()
    (tmp_path / "c.pem").write_bytes(cert)
    (tmp_path / "k.pem").write_bytes(key)
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")
    st = Stack(tmp_path, ssl_ctx=ctx)

    async def go() -> None:
        async with st.run() as c:
            r = await c.post("/v1/messages", data=body("hi"))
            assert r.status == 502 and st.seen == []

    run(go())


# --- invariant 1 ------------------------------------------------------------------------------------


def test_c36_malformed_requests_never_put_values_in_logs_or_errors(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """C-36 (invariant 1: 'never persists or emits plaintext protected values (... logs, errors ...)')."""
    st = Stack(tmp_path)
    caplog.set_level(logging.DEBUG)
    echoed: list[bytes] = []

    async def go() -> None:
        async with st.run() as c:
            assert c.port is not None
            for raw in (
                f"GET /a HTTP/1.1\r\nHost: x\r\nX-Note: {NRIC}\x00\r\n\r\n",
                f"POST /v1/messages HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n{NRIC}\r\n",
            ):
                r, w = await asyncio.open_connection("127.0.0.1", c.port)
                w.write(raw.encode("latin-1"))
                await w.drain()
                echoed.append(await asyncio.wait_for(r.read(65536), 5))
                w.close()

    run(go())
    assert NRIC not in caplog.text
    assert all(NRIC.encode() not in e for e in echoed)


# --- observation ------------------------------------------------------------------------------------


@pytest.mark.parametrize("variant", ["oversized-model-field", "deeply-nested-json"])
def test_c37_every_request_yields_a_record_or_a_counted_gap(tmp_path: Path, variant: str) -> None:
    """C-37 (ADR-0007: drops are 'coverage gaps'; app docstring: 'counts them as a coverage gap')."""
    st = Stack(tmp_path)
    payload = (
        body(f"my NRIC {NRIC}", model="x" * 20000)
        if variant == "oversized-model-field"
        else b'{"messages":[{"role":"user","content":"NRIC '
        + NRIC.encode()
        + b'"}],"pad":'
        + b"[" * 100000
        + b"]" * 100000
        + b"}"
    )

    async def go() -> None:
        async with st.run() as c:
            assert (await c.post("/v1/messages", data=payload)).status == 200

    run(go())
    assert [r for r in st.records() if r["event"] != "digest_key"] != []


def test_c41_a_slow_observer_never_delays_the_request(tmp_path: Path) -> None:
    """C-41 (app docstring: 'observation ... never delays, modifies or fails a request')."""
    st = Stack(tmp_path)

    async def go() -> None:
        async with st.run() as c:
            original = st.observer.observe

            def slow(req: Any) -> Any:
                time.sleep(1.5)
                return original(req)

            st.observer.observe = slow  # type: ignore[method-assign]
            t0 = time.perf_counter()
            r = await c.post("/v1/messages", data=body(NRIC))
            assert r.status == 200 and time.perf_counter() - t0 < 0.5

    run(go())


def test_c39_investigator_with_both_parts_can_test_a_value_and_a_session(tmp_path: Path) -> None:
    """C-39 (observe.py docstring / ADR-0009): 'an investigator with both audit parts can test a value'."""
    st = Stack(tmp_path)

    async def go() -> None:
        async with st.run() as c:
            await c.post(
                "/v1/messages", data=body(f"id {NRIC}"), headers={"x-claude-code-session-id": "sess-9"}
            )

    run(go())
    recs = st.records()
    k = bytes.fromhex(recs[0]["k_dig"])
    digest = hmac.new(k, b"ppe/obs/v1" + lp("NRIC") + lp(norm(EntityType.NRIC, NRIC)), hashlib.sha256)
    conv = hmac.new(k, b"ppe/conv/v1" + lp("sess-9"), hashlib.sha256).hexdigest()[:32]
    obs = [r for r in recs if r["event"] == "observe"]
    assert any(n["d"] == digest.hexdigest()[:32] for r in obs for n in r["new"])
    assert obs[0]["conv"] == conv


def test_c40_no_detail_headers_and_opaque_errors(tmp_path: Path) -> None:
    """C-40 (ADR-0010: no x-ppe-* detail headers in production; errors carry only an opaque reference)."""
    st = Stack(tmp_path, upstream="http://127.0.0.1:9")

    async def go() -> None:
        async with st.run(connect_timeout=2) as c:
            r = await c.post("/v1/messages", data=body(f"NRIC {NRIC}"))
            text = await r.text()
            assert r.status == 502 and NRIC not in text and "ref " in text
            assert not [h for h in r.headers if h.lower().startswith("x-ppe")]

    run(go())


# --- listener hardening (ADR-0001) -------------------------------------------------------------------


def test_c38_dns_rebinding_and_cross_origin_requests_refused(tmp_path: Path) -> None:
    """C-38 (ADR-0001: 'accept only Host localhost/127.0.0.1/[::1]; reject any Origin not allowlisted')."""
    st = Stack(tmp_path)

    async def go() -> None:
        async with st.run() as c:
            r = await c.post("/v1/messages", data=b"{}", headers={"Host": "evil.example:8787"})
            r2 = await c.post("/v1/messages", data=b"{}", headers={"Origin": "http://evil.example"})
            assert r.status in (403, 421) and r2.status == 403 and st.seen == []

    run(go())


@pytest.mark.xfail(
    strict=True, reason="F-19: '[::1]:port' passes validation, then fails to bind (brackets kept)"
)
def test_c42_bracketed_ipv6_listen_address_is_usable() -> None:
    """C-42 (ADR-0001: TCP only on 127.0.0.1/::1; '[::1]:PORT' is the standard host:port form)."""
    host, _, _ = "[::1]:8787".rpartition(":")  # what cmd_serve does
    proxy.check_listen(host)
    socket.getaddrinfo(host, 8787)


@pytest.mark.xfail(strict=True, reason="F-19: `ppe serve` takes no --policy; detection knobs are not applied")
def test_c45_serve_runs_the_configuration_explain_describes() -> None:
    """C-45 (ADR-0012 §5: `ppe explain` reads the active configuration): serve must accept the same policy."""
    build_parser().parse_args(["serve", "--policy", "policies/personal.yaml"])

"""`ppe serve` phase 2a: loopback pass-through proxy with shadow-mode observation (PLAN §5, ADR-0007).

Traffic is forwarded unchanged: body bytes in both directions (compressed bodies stay compressed,
SSE is relayed chunk by chunk as it arrives), status, and end-to-end headers. Observation runs on a
single background worker after the request is forwarded, so it never delays, modifies or fails a
request; a full backlog drops observations and counts them as a coverage gap.

Invariants (not knobs): listen on a loopback address only; a non-loopback upstream must be https;
aiohttp's compiled HTTP parser must be in use (its pure-Python fallback has had smuggling CVEs);
no redirects followed; no cookie jar shared between clients.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import secrets
import sys
from collections.abc import AsyncIterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from aiohttp import ClientError, ClientSession, ClientTimeout, DummyCookieJar, TCPConnector, web
from yarl import URL

from prompt_privacy.proxy.observe import Observer, Request

log = logging.getLogger("ppe.proxy")

# RFC 9110 §7.6.1 connection-specific fields, plus fields aiohttp computes itself.
_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)
_REQ_DROP = _HOP | {"host", "content-length"}
_RESP_DROP = _HOP
_KEY_SETTINGS: web.AppKey[Settings] = web.AppKey("settings")
_KEY_SESSION: web.AppKey[ClientSession] = web.AppKey("session")
_KEY_OBSERVER: web.AppKey[ObserverQueue] = web.AppKey("observer")


class RefusedConfig(ValueError):
    pass


@dataclass(frozen=True)
class Settings:
    upstream: str  # e.g. https://api.anthropic.com
    conversation_header: str = "x-claude-code-session-id"
    max_body: int = 64 * 1024 * 1024
    max_pending: int = 64  # queued observations before new ones are dropped (coverage gap)
    connect_timeout: float = 30.0
    read_timeout: float = 600.0  # between bytes; long generations stream slowly

    @property
    def upstream_zone(self) -> str:
        return "loopback" if _is_loopback_host(URL(self.upstream).host or "") else "cloud"

    def check(self) -> None:
        u = URL(self.upstream)
        if u.scheme not in ("http", "https") or not u.host:
            raise RefusedConfig(f"upstream must be an http(s) URL, got {self.upstream!r}")
        if u.scheme == "http" and self.upstream_zone != "loopback":
            raise RefusedConfig("a non-loopback upstream must use https")
        if u.query_string or u.fragment:
            raise RefusedConfig("upstream must not carry a query or fragment")


def _is_loopback_host(host: str) -> bool:
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return host == "localhost"


def check_listen(host: str) -> None:
    """Loopback only (PPE decision 2026-10-02). Literal addresses only: no name resolution."""
    try:
        ok = ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        ok = False
    if not ok:
        raise RefusedConfig(f"ppe serve listens on a loopback address only (127.0.0.1 or ::1), got {host!r}")


def require_compiled_parser() -> None:
    from aiohttp import http_parser

    for cls in (http_parser.HttpRequestParser, http_parser.HttpResponseParser):
        if cls.__module__ != "aiohttp._http_parser":
            raise RefusedConfig(
                "aiohttp is using its pure-Python HTTP parser (AIOHTTP_NO_EXTENSIONS set, or no compiled "
                "wheel for this platform); refusing to start"
            )


class ObserverQueue:
    """One worker thread owns the Observer (and the audit log); the event loop only submits."""

    def __init__(self, observer: Observer, max_pending: int) -> None:
        self.observer, self.max_pending = observer, max_pending
        self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ppe-observe")
        self._pending = 0
        self.failures = 0

    def submit(self, req: Request) -> asyncio.Future[object] | None:
        if self._pending >= self.max_pending:
            self._pool.submit(self._count_drop)
            return None
        self._pending += 1
        loop = asyncio.get_running_loop()
        fut = loop.run_in_executor(self._pool, self._run, req)
        fut.add_done_callback(lambda _: self._done())
        return fut

    def _done(self) -> None:
        self._pending -= 1

    def _count_drop(self) -> None:
        self.observer.dropped += 1

    def _run(self, req: Request) -> object:
        try:
            return self.observer.observe(req)
        except Exception:  # observation must never affect traffic; the failure itself is logged
            self.failures += 1
            log.exception("observation failed for request %s", req.req_id)
            return None

    def close(self) -> None:
        self._pool.shutdown(wait=True)


def _error(status: int, etype: str, message: str) -> web.Response:
    """Anthropic-format error body; the message carries an opaque reference, never request content."""
    body = {"type": "error", "error": {"type": etype, "message": message}}
    return web.Response(status=status, text=json.dumps(body), content_type="application/json")


def _forward_headers(request: web.Request) -> list[tuple[str, str]]:
    listed = {t.strip().lower() for v in request.headers.getall("Connection", []) for t in v.split(",")}
    return [
        (k, v) for k, v in request.headers.items() if k.lower() not in _REQ_DROP and k.lower() not in listed
    ]


async def _handle(request: web.Request) -> web.StreamResponse:
    settings, session = request.app[_KEY_SETTINGS], request.app[_KEY_SESSION]
    req_id = secrets.token_hex(8)
    body = await request.read()
    target = URL(settings.upstream.rstrip("/") + request.raw_path, encoded=True)
    request.app[_KEY_OBSERVER].submit(
        Request(
            req_id,
            request.method,
            request.path,
            body,
            request.headers.get(settings.conversation_header),
            settings.upstream_zone,
        )
    )
    try:
        upstream = await session.request(
            request.method,
            target,
            headers=_forward_headers(request),
            data=body or None,
            allow_redirects=False,
        )
    except (ClientError, TimeoutError) as e:
        log.warning("upstream request %s failed: %s", req_id, type(e).__name__)
        return _error(502, "api_error", f"ppe: upstream unreachable (ref {req_id})")
    async with upstream:
        resp = web.StreamResponse(status=upstream.status, reason=upstream.reason)
        listed = {t.strip().lower() for v in upstream.headers.getall("Connection", []) for t in v.split(",")}
        for k, v in upstream.headers.items():
            if k.lower() not in _RESP_DROP and k.lower() not in listed:
                resp.headers.add(k, v)
        await resp.prepare(request)
        async for chunk in upstream.content.iter_any():
            await resp.write(chunk)
        await resp.write_eof()
        return resp


def build_app(settings: Settings, observer: Observer) -> web.Application:
    settings.check()
    require_compiled_parser()
    app = web.Application(client_max_size=settings.max_body)
    app[_KEY_SETTINGS] = settings
    app[_KEY_OBSERVER] = ObserverQueue(observer, settings.max_pending)

    async def lifecycle(app: web.Application) -> AsyncIterator[None]:
        app[_KEY_SESSION] = ClientSession(
            connector=TCPConnector(limit=0),
            cookie_jar=DummyCookieJar(),
            auto_decompress=False,  # relay bodies byte for byte, Content-Encoding intact
            skip_auto_headers=("User-Agent", "Accept", "Accept-Encoding", "Content-Type"),
            timeout=ClientTimeout(
                total=None, sock_connect=settings.connect_timeout, sock_read=settings.read_timeout
            ),
        )
        yield
        await app[_KEY_SESSION].close()
        app[_KEY_OBSERVER].close()

    app.cleanup_ctx.append(lifecycle)
    app.router.add_route("*", "/{tail:.*}", _handle)
    return app


def serve(settings: Settings, observer: Observer, host: str, port: int) -> None:
    check_listen(host)
    app = build_app(settings, observer)
    print(
        f"ppe serve: http://{host}:{port} -> {settings.upstream} ({settings.upstream_zone}), shadow mode",
        file=sys.stderr,
    )
    web.run_app(app, host=host, port=port, access_log=None, print=None)

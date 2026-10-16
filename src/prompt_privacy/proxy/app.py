"""`ppe serve` phase 2a: loopback pass-through proxy with shadow-mode observation (PLAN §5, ADR-0007).

Traffic is forwarded unchanged: body bytes in both directions (compressed bodies stay compressed,
SSE is relayed chunk by chunk as it arrives), status, and end-to-end headers. Once the body is read
it is queued for observation on a single background worker that runs alongside the relay, so
observation never delays, modifies or fails a request; a full backlog drops observations and counts
them (carried into the next record and the shutdown record).

Invariants (not knobs): listen on a loopback address only; a non-loopback upstream must be https;
aiohttp's compiled HTTP parser must be in use (its pure-Python fallback has had smuggling CVEs);
no redirects followed; no cookie jar shared between clients; request bodies are never decoded on the
relay path (the observer decodes a bounded copy); `Host` must name a loopback address and a browser
`Origin` is refused unless allowlisted (DNS rebinding, ADR-0001); errors raised before routing (parser
errors) and handler crashes get an opaque body and are logged by exception type only, never with
request bytes (invariant 1). The last two need the protocol handler installed by `ProxyRunner`.
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
from typing import Any

from aiohttp import ClientError, ClientSession, ClientTimeout, DummyCookieJar, TCPConnector, web
from aiohttp.web_request import BaseRequest
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
    allowed_origins: tuple[str, ...] = ()  # browser origins allowed to call the proxy; none by default

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


def _host_allowed(value: str | None) -> bool:
    """`Host` is `localhost` or a loopback address literal, with an optional port. A DNS-rebinding page
    reaches the listener under its own name, so a name other than `localhost` is refused."""
    if not value:
        return False
    v = value.lower()
    if v.startswith("["):
        host, sep, rest = v[1:].partition("]")
        return bool(sep) and ":" in host and _port_ok(rest) and _is_loopback_host(host)
    host, sep, port = v.partition(":")
    return (not sep or _port_ok(":" + port)) and _is_loopback_host(host)


def _port_ok(rest: str) -> bool:
    return rest == "" or (rest[:1] == ":" and rest[1:].isascii() and rest[1:].isdigit() and len(rest) <= 6)


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
        except Exception as e:  # not even a gap record could be written (e.g. audit file unwritable)
            self.observer.failed += 1
            log.error("observation of request %s not recorded: %s", req.req_id, type(e).__name__)
            return None

    def close(self) -> None:
        self._pool.submit(self._stop)
        self._pool.shutdown(wait=True)

    def _stop(self) -> None:
        try:
            health = self.observer.stop()
        except Exception as e:
            log.error("observer shutdown record not written: %s", type(e).__name__)
            return
        print(f"ppe serve: observation {json.dumps(health, sort_keys=True)}", file=sys.stderr)


def _error(status: int, etype: str, message: str) -> web.Response:
    """Anthropic-format error body; the message carries an opaque reference, never request content."""
    body = {"type": "error", "error": {"type": etype, "message": message}}
    return web.Response(status=status, text=json.dumps(body), content_type="application/json")


def _listener_refusal(settings: Settings, request: web.Request, req_id: str) -> web.Response | None:
    if len(request.headers.getall("Host", [])) > 1 or not _host_allowed(request.headers.get("Host")):
        log.warning("request %s refused: Host is not a loopback name", req_id)
        return _error(421, "invalid_request_error", f"ppe: Host not allowed (ref {req_id})")
    origins = request.headers.getall("Origin", [])
    if origins and not all(o in settings.allowed_origins for o in origins):
        log.warning("request %s refused: Origin not allowlisted", req_id)
        return _error(403, "permission_error", f"ppe: Origin not allowed (ref {req_id})")
    return None


def _forward_headers(request: web.Request) -> list[tuple[str, str]]:
    listed = {t.strip().lower() for v in request.headers.getall("Connection", []) for t in v.split(",")}
    return [
        (k, v) for k, v in request.headers.items() if k.lower() not in _REQ_DROP and k.lower() not in listed
    ]


def _target(settings: Settings, request: web.Request) -> URL | None:
    """Origin-form targets only; no dot segments (raw or %-encoded); the result stays on the upstream."""
    raw = request.raw_path
    if request.method == "CONNECT" or not raw.startswith("/"):
        return None
    if any(seg in (".", "..") for seg in request.path.split("/")):
        return None
    base = URL(settings.upstream)
    target = URL(settings.upstream.rstrip("/") + raw, encoded=True)
    if (target.scheme, target.host, target.port) != (base.scheme, base.host, base.port):
        return None
    return target


async def _handle(request: web.Request) -> web.StreamResponse:
    settings, session = request.app[_KEY_SETTINGS], request.app[_KEY_SESSION]
    req_id = secrets.token_hex(8)
    if not isinstance(request.protocol, _OpaqueErrors):
        # Served by a stock runner (web.run_app, a plain TestServer): its parser-error path would echo
        # and log request bytes (F-05), so refuse all traffic rather than run half-protected.
        log.error("request %s refused: the proxy must be served by ProxyRunner", req_id)
        return _error(500, "api_error", f"ppe: proxy misconfigured (ref {req_id})")
    refusal = _listener_refusal(settings, request, req_id)
    if refusal is not None:
        return refusal
    try:
        target = _target(settings, request)
    except ValueError:
        target = None
    if target is None:
        return _error(400, "invalid_request_error", f"ppe: request target refused (ref {req_id})")
    body = await request.read()
    request.app[_KEY_OBSERVER].submit(
        Request(
            req_id,
            request.method,
            request.path,
            body,
            request.headers.get(settings.conversation_header),
            settings.upstream_zone,
            encoding=request.headers.get("Content-Encoding"),
            query=request.query_string,
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
    """The proxy application. Serve it with `ProxyRunner` (as `serve` does); under any other runner
    every request is refused with an opaque 500, because only `ProxyRunner`'s protocol handler keeps
    request bytes out of parser-error bodies and logs."""
    settings.check()
    require_compiled_parser()
    # auto_decompress=False: the relay forwards the client's bytes, Content-Encoding intact (F-04).
    app = web.Application(client_max_size=settings.max_body, handler_args={"auto_decompress": False})
    app[_KEY_SETTINGS] = settings
    observer.max_decoded = min(observer.max_decoded, settings.max_body)  # same cap, decoded or not
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


class _OpaqueErrors(web.RequestHandler):
    """aiohttp's protocol handler, minus request bytes in error bodies and logs (invariant 1, F-05).

    The stock handler echoes the parser's message (which quotes the offending bytes) in the 400 body
    and logs it with a traceback; with no logging configured, Python's last-resort handler prints that
    to stderr and from there to journald. Here the body is a fixed message with an opaque reference
    and the log line names the exception type only.
    """

    def handle_error(
        self,
        request: BaseRequest,
        status: int = 500,
        exc: BaseException | None = None,
        message: str | None = None,
    ) -> web.StreamResponse:
        ref = secrets.token_hex(8)
        log.warning("request %s failed before relay: HTTP %d, %s", ref, status, type(exc).__name__)
        if request.writer.output_size > 0:
            raise ConnectionError("response already started")
        etype = "invalid_request_error" if status < 500 else "api_error"
        resp = _error(status, etype, f"ppe: request refused (ref {ref})")
        resp.force_close()
        return resp

    def log_exception(self, *args: object, **kw: object) -> None:
        exc = kw.get("exc_info")
        name = type(exc).__name__ if isinstance(exc, BaseException) else "error"
        log.error("aiohttp: unhandled %s", name)

    def log_debug(self, *args: object, **kw: object) -> None:
        pass


class _Server(web.Server):
    def __call__(self) -> web.RequestHandler:
        return _OpaqueErrors(self, loop=self._loop, **self._kwargs)


class ProxyRunner(web.AppRunner):
    """An AppRunner whose connections use `_OpaqueErrors` and never write an access log (the request
    line carries the path and query, which can hold identifiers). `ppe serve` and the tests run this."""

    def __init__(self, app: web.Application, **kwargs: Any) -> None:
        super().__init__(app, **{**kwargs, "access_log": None})

    async def _make_server(self) -> web.Server:
        s = await super()._make_server()
        return _Server(
            s.request_handler,
            request_factory=s.request_factory,
            handler_cancellation=s.handler_cancellation,
            loop=s._loop,
            **s._kwargs,
        )


class _QuietAiohttp(logging.Filter):
    """Belt and braces for any aiohttp/asyncio log path not covered by `_OpaqueErrors`: drop arguments
    and tracebacks (which can quote request bytes), keep the message template and exception type."""

    def filter(self, record: logging.LogRecord) -> bool:
        if record.args or record.exc_info:
            exc = record.exc_info[1] if record.exc_info else None
            record.msg = f"{record.msg} [details withheld{': ' + type(exc).__name__ if exc else ''}]"
            record.args, record.exc_info, record.exc_text = None, None, None
        return True


def quiet_library_logs() -> None:
    for name in ("aiohttp", "aiohttp.server", "aiohttp.access", "aiohttp.web", "aiohttp.client", "asyncio"):
        logger = logging.getLogger(name)
        if not any(isinstance(f, _QuietAiohttp) for f in logger.filters):
            logger.addFilter(_QuietAiohttp())


async def _run(app: web.Application, host: str, port: int) -> None:
    runner = ProxyRunner(app, handle_signals=True)
    await runner.setup()
    try:
        await web.TCPSite(runner, host, port).start()
        await asyncio.Event().wait()
    finally:
        await runner.cleanup()


def serve(settings: Settings, observer: Observer, host: str, port: int) -> None:
    check_listen(host)
    quiet_library_logs()
    app = build_app(settings, observer)
    print(
        f"ppe serve: http://{host}:{port} -> {settings.upstream} ({settings.upstream_zone}), shadow mode",
        file=sys.stderr,
    )
    try:
        asyncio.run(_run(app, host, port))
    except (KeyboardInterrupt, web.GracefulExit):
        pass

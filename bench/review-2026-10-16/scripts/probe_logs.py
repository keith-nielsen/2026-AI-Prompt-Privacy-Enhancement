"""Invariant 1 probe: does anything PPE runs write a protected value to logs? (synthetic NRIC)"""
import asyncio, io, logging, tempfile, json
from pathlib import Path
from aiohttp import web
from aiohttp.test_utils import TestServer
from prompt_privacy.audit.keys import AuditKeyPair
from prompt_privacy.audit.log import AuditLog
from prompt_privacy.proxy import app as proxy
from prompt_privacy.proxy.observe import Observer

NRIC = "S1234567D"
buf = io.StringIO()
logging.basicConfig(stream=buf, level=logging.WARNING)  # the level Python's last-resort stderr handler emits

async def main():
    async def h(r):
        await r.read(); return web.Response(body=b"ok")
    upa = web.Application(); upa.router.add_route("*", "/{t:.*}", h)
    up = TestServer(upa, host="127.0.0.1"); await up.start_server()
    m, t = AuditKeyPair.generate(), AuditKeyPair.generate()
    d = Path(tempfile.mkdtemp())
    obs = Observer(AuditLog(d / "a.jsonl", m.public, t.public, "lab"))
    px = TestServer(proxy.build_app(proxy.Settings(upstream=str(up.make_url("/")).rstrip("/")), obs), host="127.0.0.1")
    await px.start_server()
    payloads = {
        "bad header (NUL) carrying NRIC": f"GET /a HTTP/1.1\r\nHost: x\r\nX-Note: {NRIC}\x00\r\n\r\n",
        "bad chunk size carrying NRIC": f"POST /v1/messages HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n{NRIC}\r\nabc\r\n0\r\n\r\n",
        "bad request line carrying NRIC": f"GET /a?id={NRIC} HTTP/1.1 x\r\nHost: x\r\n\r\n",
        "obs-fold carrying NRIC": f"POST /a HTTP/1.1\r\nHost: x\r\nX-A: 1\r\n  {NRIC}\r\nContent-Length: 0\r\n\r\n",
    }
    for name, raw in payloads.items():
        r, w = await asyncio.open_connection("127.0.0.1", px.port)
        w.write(raw.encode("latin-1")); await w.drain()
        try:
            data = await asyncio.wait_for(r.read(65536), 2)
        except asyncio.TimeoutError:
            data = b""
        w.close()
        print(f"{name:34} response echoes NRIC: {NRIC.encode() in data}")
    await asyncio.sleep(0.2)
    await px.close(); await up.close()

asyncio.run(main())
logs = buf.getvalue()
print(f"log output: {len(logs)} chars; NRIC present in logs: {NRIC in logs} ({logs.count(NRIC)} times)")
for line in logs.splitlines():
    if NRIC in line:
        print("   e.g.:", line[:160]); break

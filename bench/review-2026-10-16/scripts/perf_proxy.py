"""ppe serve overhead: added latency per request, and whether a large prompt's scan stalls a concurrent stream."""
import asyncio, json, statistics, tempfile, time
from pathlib import Path
from aiohttp import web, ClientSession
from aiohttp.test_utils import TestServer
from prompt_privacy.audit.keys import AuditKeyPair
from prompt_privacy.audit.log import AuditLog
from prompt_privacy.proxy import app as proxy
from prompt_privacy.proxy.observe import Observer
from prompt_privacy.corpus.generator import Generator

ITEMS = [i.text for i in Generator(20261002).items(3000)]
def doc(n):
    out, k = [], 0
    while sum(len(x) for x in out) < n:
        out.append(ITEMS[k % len(ITEMS)]); k += 1
    return "\n".join(out)[:n]

async def main():
    gaps = []
    async def up_handler(r):
        await r.read()
        if r.path == "/stream":
            resp = web.StreamResponse(); await resp.prepare(r)
            for _ in range(200):
                await resp.write(b"data: x\n\n"); await asyncio.sleep(0.005)
            await resp.write_eof(); return resp
        return web.Response(body=b'{"ok":true}')
    upa = web.Application(client_max_size=1 << 28); upa.router.add_route("*", "/{t:.*}", up_handler)
    up = TestServer(upa, host="127.0.0.1"); await up.start_server()
    m, t = AuditKeyPair.generate(), AuditKeyPair.generate()
    obs = Observer(AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl", m.public, t.public, "lab"))
    px = TestServer(proxy.build_app(proxy.Settings(upstream=str(up.make_url("/")).rstrip("/")), obs), host="127.0.0.1")
    await px.start_server()
    async with ClientSession() as s:
        async def lat(url, body, n=200):
            ts = []
            for i in range(n):
                t0 = time.perf_counter()
                async with s.post(url, data=body) as r:
                    await r.read()
                ts.append((time.perf_counter() - t0) * 1000)
            ts.sort(); return statistics.median(ts), ts[int(len(ts) * 0.99) - 1]
        small = json.dumps({"model": "m", "messages": [{"role": "user", "content": "hello S1234567D"}]}).encode()
        for label, base in (("direct to upstream", up.make_url("")), ("through ppe serve", px.make_url(""))):
            p50, p99 = await lat(str(base) + "/v1/messages", small)
            print(f"small request {label:20} p50 {p50:6.2f} ms  p99 {p99:6.2f} ms")
        # throughput, 32 concurrent clients, 2000 requests
        async def one():
            async with s.post(str(px.make_url("/v1/messages")), data=small) as r:
                await r.read()
        t0 = time.perf_counter()
        for i in range(0, 2000, 32):
            await asyncio.gather(*(one() for _ in range(32)))
        print(f"throughput through ppe serve (32 concurrent): {2000/(time.perf_counter()-t0):7.0f} req/s (each also fsyncs a sealed record)")
        # GIL: stream inter-chunk gaps while a 2 MB prompt is being scanned
        async def stream_gaps():
            last = None; g = []
            async with s.get(str(px.make_url("/stream"))) as r:
                async for _ in r.content.iter_any():
                    now = time.perf_counter()
                    if last is not None: g.append((now - last) * 1000)
                    last = now
            return g
        base_g = await stream_gaps()
        big = json.dumps({"model": "m", "messages": [{"role": "user", "content": doc(2_000_000)}]}).encode()
        async def big_post():
            await asyncio.sleep(0.2)
            t0 = time.perf_counter()
            async with s.post(str(px.make_url("/v1/messages")), data=big) as r:
                await r.read()
            return (time.perf_counter() - t0) * 1000
        g, big_ms = await asyncio.gather(stream_gaps(), big_post())
        print(f"stream chunk gap idle:        max {max(base_g):6.1f} ms  p99 {sorted(base_g)[-3]:6.1f} ms")
        print(f"stream chunk gap during 2 MB prompt scan: max {max(g):6.1f} ms  p99 {sorted(g)[-3]:6.1f} ms  (2 MB request itself {big_ms:.0f} ms)")
    await px.close(); await up.close()
asyncio.run(main())

"""Review probes for ppe serve (fake upstreams on loopback only; synthetic data)."""
import asyncio, gzip, json, ssl, subprocess, tempfile, hashlib, hmac, traceback
from pathlib import Path
from aiohttp import web
from aiohttp.test_utils import TestServer, TestClient
from prompt_privacy.audit.keys import AuditKeyPair
from prompt_privacy.audit.log import AuditLog, open_log
from prompt_privacy.proxy import app as proxy
from prompt_privacy.proxy.observe import Observer
from prompt_privacy.core.normalise import norm
from prompt_privacy.core.types import EntityType
from prompt_privacy.core.keys import lp

def out(k, v): print(f"{k:62} {v}", flush=True)
NRIC = "S1234567D"
TMP = Path(tempfile.mkdtemp())

def echo_app(seen):
    async def h(r):
        b = await r.read()
        seen.append((dict(r.headers), b))
        return web.Response(body=b"ok")
    a = web.Application(client_max_size=1 << 30, handler_args={"auto_decompress": False})
    a.router.add_route("*", "/{t:.*}", h)
    return a

class Stack:
    async def __aenter__(self):
        self.seen = []
        self.up = TestServer(echo_app(self.seen), host="127.0.0.1"); await self.up.start_server()
        self.m, self.t = AuditKeyPair.generate(), AuditKeyPair.generate()
        self.d = Path(tempfile.mkdtemp(dir=TMP))
        self.obs = Observer(AuditLog(self.d / "a.jsonl", self.m.public, self.t.public, "lab"))
        app = proxy.build_app(proxy.Settings(upstream=str(self.up.make_url("/")).rstrip("/"), **self.kw), self.obs)
        self.c = TestClient(TestServer(app, host="127.0.0.1")); await self.c.start_server()
        return self
    def __init__(self, **kw): self.kw = kw
    async def __aexit__(self, *a):
        await self.c.close(); await self.up.close()
    def records(self):
        return list(open_log(self.d / "a.jsonl", self.m, self.t))

def body(text, model="m"):
    return json.dumps({"model": model, "messages": [{"role": "user", "content": text}]}).encode()

async def p1():
    async with Stack() as s:
        gz = gzip.compress(body(f"NRIC {NRIC}"))
        await s.c.post("/v1/messages", data=gz, headers={"Content-Encoding": "gzip", "Content-Type": "application/json"})
        h, b = s.seen[-1]
        out("P1 gzip request body forwarded byte-identical", f"{b == gz} (sent {len(gz)} B gz, upstream got {len(b)} B, CE={h.get('Content-Encoding')}, starts {b[:12]!r})")
    recs = [r for r in s.records() if r["event"] == "observe"]
    out("P1  observation of the gzip request", [(r.get("scanned"), r.get("reason"), len(r.get("new", []))) for r in recs])

async def p1b():
    async with Stack() as s:
        bomb = gzip.compress(b"\0" * (200 * 1024 * 1024))
        r = await asyncio.wait_for(s.c.post("/v1/messages", data=bomb, headers={"Content-Encoding": "gzip"}), 120)
        out(f"P1b 200 MiB gzip bomb ({len(bomb)//1024} KiB compressed): status / forwarded", f"{r.status} / {len(s.seen)}")

async def p2():
    async with Stack() as s:
        r = await s.c.post("/v1/messages", data=b"{}", headers={"Host": "evil.example:8787", "Origin": "http://evil.example"})
        out("P2 Host: evil.example + Origin: http://evil.example", f"status {r.status}, forwarded={len(s.seen)}")
        r = await s.c.get("/../x")
        out("P2 Server header on a PPE-generated 400", r.headers.get("Server"))

async def p5():
    async with Stack() as s:
        await s.c.post("/v1/messages", data=body(f"my NRIC {NRIC}", model="x" * 20000))
        deep = b'{"model":"m","messages":[{"role":"user","content":"NRIC ' + NRIC.encode() + b'"}],"pad":' + b"[" * 100000 + b"]" * 100000 + b"}"
        await s.c.post("/v1/messages", data=deep)
        await s.c.post("/v1/messages?" + "q=" + "a" * 6000, data=body(" ".join(f"u{i}@example.com" for i in range(99))))
        await s.c.post("/v1/messages", data=body("control: " + NRIC))
        fails = s.obs
    recs = [r for r in s.records() if r["event"] == "observe"]
    out("P5 4 requests with an NRIC/emails -> observe records", f"{len(recs)}: {[(r.get('scanned'), r.get('reason'), len(r.get('new', []))) for r in recs]}")

async def p6():
    async with Stack() as s:
        (s.d / "a.jsonl").chmod(0o400)
        r = await s.c.post("/v1/messages", data=body(NRIC))
        await asyncio.sleep(0.3)
        out("P6 audit log read-only: status / forwarded", f"{r.status} / {len(s.seen)} (observation lost silently; only a log line)")
    (s.d / "a.jsonl").chmod(0o600)

async def p23():
    async with Stack() as s:
        await s.c.post("/v1/messages", data=body(f"id {NRIC}"), headers={"x-claude-code-session-id": "sess-9"})
    recs = s.records()
    k = bytes.fromhex(recs[0]["k_dig"])
    want = hmac.new(k, b"ppe/obs/v1" + lp("NRIC") + lp(norm(EntityType.NRIC, NRIC)), hashlib.sha256).hexdigest()[:32]
    out("P23 investigator (both parts) finds a known NRIC by digest", any(n["d"] == want for r in recs if r["event"] == "observe" for n in r.get("new", [])))
    conv = hmac.new(k, b"ppe/conv/v1" + lp("sess-9"), hashlib.sha256).hexdigest()[:32]
    out("P23 investigator links a known session id to its records", any(r.get("conv") == conv for r in recs))

async def p3():
    cert_dir = Path(tempfile.mkdtemp(dir=TMP))
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                    "-keyout", str(cert_dir / "k.pem"), "-out", str(cert_dir / "c.pem"), "-days", "1",
                    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"], check=True, capture_output=True)
    sslctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH); sslctx.load_cert_chain(cert_dir / "c.pem", cert_dir / "k.pem")
    seen = []
    up = TestServer(echo_app(seen), host="127.0.0.1", ssl=sslctx); await up.start_server()
    m, t = AuditKeyPair.generate(), AuditKeyPair.generate()
    obs = Observer(AuditLog(cert_dir / "a.jsonl", m.public, t.public, "lab"))
    c = TestClient(TestServer(proxy.build_app(proxy.Settings(upstream=f"https://127.0.0.1:{up.port}"), obs), host="127.0.0.1"))
    await c.start_server()
    r = await c.post("/v1/messages", data=b"{}")
    out("P3 self-signed https upstream: status / forwarded", f"{r.status} / {len(seen)}")
    await c.close(); await up.close()

async def p25():
    s = proxy.Settings(upstream="http://localhost:9")
    try:
        s.check(); out("P25 http://localhost upstream -> zone (resolver-dependent)", s.upstream_zone)
    except proxy.RefusedConfig as e:
        out("P25 http://localhost upstream", f"refused: {e}")

async def main():
    for p in (p1, p1b, p2, p5, p6, p23, p3, p25):
        try:
            await p()
        except Exception as e:
            out(f"{p.__name__} probe error", f"{type(e).__name__}: {e}"[:200])
asyncio.run(main())

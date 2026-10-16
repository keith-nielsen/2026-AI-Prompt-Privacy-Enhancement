"""Black-box validation of the review's "Now" fixes (F-01, F-03 wording, F-04, F-05, F-06, F-08, F-11,
F-14, F-20) against any source tree, through its public surfaces only: the `ppe` CLI, a real
`ppe serve` process, and the files in the tree. Synthetic data only; loopback only; nothing leaves
the host.

    python validate_now_fixes.py <tree>      # e.g. a worktree of 2656090 (before) or the repo (after)

Each check is one of:
  FIX   the fixed behaviour. Expected: FAIL on the pre-fix tree (the check has teeth), PASS after.
  CTRL  a control that proves the harness itself works (the planted value really flowed, the scanner
        really flags a bad sample, the good request really succeeds). Expected: PASS on both trees.
  TRUTH a documented statement checked against behaviour (e.g. the README's stated audit limit).
        Expected: PASS on both trees (the behaviour did not change; the docs now say so).

Exit status 0 only if every check passes.
"""

from __future__ import annotations

import asyncio
import gzip
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from aiohttp import web

TREE = Path(sys.argv[1]).resolve()
PY = sys.executable
ENV = {**os.environ, "PYTHONPATH": str(TREE / "src")}
NRIC = "S1234567D"  # widely published sample value
TMP = Path(tempfile.mkdtemp(prefix="ppe-validate-"))
RESULTS: list[tuple[str, str, bool, str]] = []


def check(cid: str, kind: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((cid, kind, ok, detail))
    print(f"{cid:34} {kind:5} {'PASS' if ok else 'FAIL'}  {detail}", flush=True)


def ppe(*args: str, timeout: float = 120) -> subprocess.CompletedProcess[str]:
    code = "import sys; from prompt_privacy.cli.main import main; sys.exit(main(sys.argv[1:]))"
    return subprocess.run(
        [PY, "-c", code, *args], env=ENV, capture_output=True, text=True, timeout=timeout, cwd=TREE
    )


def tree_py(code: str, timeout: float = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [PY, "-c", code], env=ENV, capture_output=True, text=True, timeout=timeout, cwd=TREE
    )


def tracked(pattern: str) -> list[Path]:
    out = subprocess.run(["git", "-C", str(TREE), "ls-files", pattern], capture_output=True, text=True)
    return [TREE / p for p in out.stdout.split()]


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def keys(d: Path) -> None:
    r = ppe("audit", "keygen", "--dir", str(d), "--dev-token")
    assert r.returncode == 0, r.stderr


def open_records(d: Path, log: Path) -> list[dict[str, Any]]:
    r = ppe(
        "audit",
        "open",
        "--dir",
        str(d),
        "--log",
        str(log),
        "--machine-key",
        str(d / "machine.key"),
        "--dev-token",
    )
    if r.returncode != 0:
        return []
    return [json.loads(line) for line in r.stdout.splitlines() if line.strip()]


# --- F-01, F-03 wording, F-20: the tree's files ----------------------------------------------------


def docs_checks() -> None:
    markup = re.compile("<" + r"/?(?:invoke|parameter)\b|<" + "/content>")
    check("F01.ctl.pattern-flags-sample", "CTRL", bool(markup.search("text\n<" + "/invoke>\n")))
    offenders = [p.relative_to(TREE).as_posix() for p in tracked("*.md") if markup.search(p.read_text())]
    check("F01.fix.no-markup-in-docs", "FIX", offenders == [], f"{len(offenders)} file(s) with markup")
    readme = (TREE / "README.md").read_text()
    check("F01.fix.no-script-in-readme", "FIX", "git branch -f" not in readme)

    check(
        "F03.fix.no-overclaim",
        "FIX",
        "attacker-proof" not in readme and "tamper-evident" not in readme.split("## Limits")[0],
    )
    check("F03.fix.limit-stated", "FIX", "signed checkpoints" in readme and "truncation" in readme)

    for name in ("SECURITY.md", "CONTRIBUTING.md"):
        t = (TREE / name).read_text().lower()
        check(
            f"F20.fix.{name.split('.')[0].lower()}-current",
            "FIX",
            "no executable code" not in t and "design phase" not in t,
        )
    last = sorted(p.name[:8] for p in (TREE / "docs/design").glob("ADR-*.md"))[-1]
    check("F20.fix.readme-adr-index", "FIX", f"ADR-0001 … {last}" in readme, f"last ADR {last}")
    plan = (TREE / "docs/design/PLAN.md").read_text()
    tm = (TREE / "docs/threat-model.md").read_text()
    check(
        "F20.fix.plan-and-threat-model-status",
        "FIX",
        "Nothing built" not in plan and "nothing is built" not in tm,
    )
    check("F20.fix.built-vs-designed-table", "FIX", "## Built and designed" in readme)
    r = tree_py(
        "from prompt_privacy import knobs, policy\n"
        "leaves=[]\n"
        "def walk(n,p=''):\n"
        "    for k,v in (n.get('properties') or {}).items():\n"
        "        (walk(v,p+k+'.') if v.get('type')=='object' and 'properties' in v else leaves.append(p+k))\n"
        "walk(policy.schema('policy'))\n"
        "print([l for l in leaves if l!='profile' and l not in {k.path for k in knobs.KNOBS}])\n"
        "pol={'profile':'team','detection':{'dictionary':[{'term':'Project Falcon','type':'TERM'}]}}\n"
        "t=knobs.explain(pol)\n"
        "print('detection.dictionary' in t, 'Falcon' in t)\n"
    )
    lines = r.stdout.splitlines()
    check(
        "F20.fix.every-setting-has-a-knob",
        "FIX",
        r.returncode == 0 and lines[:1] == ["[]"],
        lines[0] if lines else r.stderr[-200:],
    )
    check(
        "F20.fix.explain-hides-dictionary-terms",
        "FIX",
        lines[1:2] == ["True False"],
        lines[1] if len(lines) > 1 else r.stderr[-200:],
    )

    # ADR-0002 amendment: tokens use RFC 4648 base32 (a-z2-7), not Crockford (which has no i, l, o, u).
    r = tree_py(
        "from prompt_privacy.core.surrogates import Surrogator\n"
        "from prompt_privacy.core.keys import TokenKey\n"
        "from prompt_privacy.core.types import EntityType\n"
        "s=Surrogator(TokenKey(bytes(range(32))))\n"
        "suf=''.join(s.token('c',EntityType.EMAIL,f'u{i}@example.com').canonical.split('_',1)[1][:-1] for i in range(300))\n"
        "print(set(suf)<=set('abcdefghijklmnopqrstuvwxyz234567'), bool(set(suf)&set('ilou')))\n"
    )
    check("F20.truth.adr0002-rfc4648-base32", "TRUTH", r.stdout.strip() == "True True", r.stdout.strip())
    adr2 = (TREE / "docs/design/ADR-0002-swap-and-restore.md").read_text()
    check("F20.fix.adr0002-amendment", "FIX", "RFC 4648" in adr2)


# --- F-10/ADR-0010 truth and F-11: the audit log via the CLI -------------------------------------------


def audit_checks() -> None:
    d = TMP / "audit-keys"
    keys(d)
    # ADR-0010 amendment: every profile other than lab refuses the dev token.
    refused = []
    for prof in ("personal", "team", "regulated", "high-assurance"):
        r = ppe(
            "audit",
            "append",
            '{"event":"x"}',
            "--dir",
            str(d),
            "--log",
            str(TMP / f"p-{prof}.jsonl"),
            "--profile",
            prof,
        )
        refused.append(r.returncode != 0 and "DevKeyRefused" in r.stderr)
    check("F20.truth.adr0010-dev-token-only-in-lab", "TRUTH", all(refused), str(refused))
    r = ppe("audit", "append", '{"event":"x"}', "--dir", str(d), "--log", str(TMP / "p-lab.jsonl"))
    check("F20.ctl.dev-token-accepted-in-lab", "CTRL", r.returncode == 0)

    # F-11: four processes, each holding one writer object (like `ppe serve` plus `ppe audit append`),
    # append 50 records each at the same moment.
    log = TMP / "shared.jsonl"
    start = time.time() + 1.5
    writer = (
        "import sys,time; from pathlib import Path\n"
        "from prompt_privacy.audit.keys import AuditPublicKey\n"
        "from prompt_privacy.audit.log import AuditLog\n"
        f"d=Path({str(d)!r}); w=AuditLog(Path({str(log)!r}),AuditPublicKey((d/'machine.pub').read_bytes()),"
        "AuditPublicKey((d/'token.pub').read_bytes()),'lab')\n"
        f"time.sleep(max(0,{start}-time.time()))\n"
        "for i in range(50): w.append({'event':'w','w':sys.argv[1],'i':i})\n"
    )
    procs = [subprocess.Popen([PY, "-c", writer, str(n)], env=ENV, cwd=TREE) for n in range(4)]
    for p in procs:
        p.wait(120)
    v = ppe("audit", "verify", "--log", str(log))
    check(
        "F11.fix.four-concurrent-writers",
        "FIX",
        v.returncode == 0 and "200 record" in v.stdout,
        v.stdout.strip(),
    )

    good = TMP / "good.jsonl"
    for i in range(3):
        ppe("audit", "append", json.dumps({"event": "g", "i": i}), "--dir", str(d), "--log", str(good))
    lines = good.read_text().splitlines()
    bad = TMP / "reordered.jsonl"
    bad.write_text("\n".join([lines[0], lines[2], lines[1]]) + "\n")
    check("F11.ctl.verify-detects-reorder", "CTRL", ppe("audit", "verify", "--log", str(bad)).returncode == 1)
    trunc = TMP / "truncated.jsonl"
    trunc.write_text("\n".join(lines[:2]) + "\n")
    t = ppe("audit", "verify", "--log", str(trunc))
    check(
        "F03.truth.tail-truncation-not-detected",
        "TRUTH",
        t.returncode == 0,
        "README limit: truncation passes verify until signed checkpoints exist",
    )

    torn = TMP / "torn.jsonl"
    shutil.copy(good, torn)
    with torn.open("a") as f:
        f.write('{"v":2,"seq":3,"prev":"ab')
    r = ppe("audit", "verify", "--log", str(torn))
    check(
        "F11.fix.torn-tail-reported",
        "FIX",
        r.returncode == 1 and "torn" in r.stdout.lower(),
        (r.stdout.strip() or r.stderr.strip().splitlines()[-1])[:90],
    )
    r = ppe("audit", "append", '{"event":"after-crash"}', "--dir", str(d), "--log", str(torn))
    v = ppe("audit", "verify", "--log", str(torn))
    events = [rec.get("event") for rec in open_records(d, torn)]
    check(
        "F11.fix.writer-recovers-torn-tail",
        "FIX",
        r.returncode == 0 and v.returncode == 0 and events[-2:] == ["recovered", "after-crash"],
        f"append rc={r.returncode}, verify={v.stdout.strip()}, last events={events[-2:]}",
    )


# --- F-04, F-05, F-06, F-08: a real `ppe serve` -------------------------------------------------------


class Upstream:
    """Raw upstream on loopback: records method, path, headers and the exact body bytes it received."""

    def __init__(self) -> None:
        self.seen: list[tuple[str, str, dict[str, str], bytes]] = []
        self.port = free_port()
        self.loop = asyncio.new_event_loop()
        self.ready = threading.Event()
        threading.Thread(target=self._run, daemon=True).start()
        self.ready.wait(10)

    def _run(self) -> None:
        asyncio.set_event_loop(self.loop)

        async def h(r: web.Request) -> web.Response:
            self.seen.append((r.method, r.raw_path, dict(r.headers), await r.read()))
            return web.Response(body=b'{"ok":true}', content_type="application/json")

        app = web.Application(client_max_size=1 << 30, handler_args={"auto_decompress": False})
        app.router.add_route("*", "/{t:.*}", h)
        runner = web.AppRunner(app, access_log=None)
        self.loop.run_until_complete(runner.setup())
        self.loop.run_until_complete(web.TCPSite(runner, "127.0.0.1", self.port).start())
        self.ready.set()
        self.loop.run_forever()


def raw(port: int, payload: bytes, wait: float = 1.0) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(payload)
        s.settimeout(wait)
        data = b""
        try:
            while chunk := s.recv(65536):
                data += chunk
        except TimeoutError:
            pass
    return data


def post(
    port: int, path: str, body: bytes, headers: dict[str, str] | None = None, host: str | None = None
) -> tuple[int, bytes]:
    h = {
        "Host": host or f"127.0.0.1:{port}",
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
        "Connection": "close",
        **(headers or {}),
    }
    head = f"POST {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in h.items()) + "\r\n"
    resp = raw(port, head.encode() + body, wait=5)
    status = int(resp[9:12]) if resp.startswith(b"HTTP/1.") else 0
    return status, resp


def msg(text: str, model: str = "claude-test", pad: int = 0) -> bytes:
    return json.dumps(
        {"model": model, "pad": "p" * pad, "messages": [{"role": "user", "content": text}]}
    ).encode()


def proxy_checks() -> None:
    d = TMP / "serve-keys"
    keys(d)
    log = TMP / "serve.jsonl"
    up = Upstream()
    port = free_port()
    err = (TMP / "serve.err").open("w")
    srv = subprocess.Popen(
        [
            PY,
            "-c",
            "import sys; from prompt_privacy.cli.main import main; sys.exit(main(sys.argv[1:]))",
            "serve",
            "--listen",
            f"127.0.0.1:{port}",
            "--upstream",
            f"http://127.0.0.1:{up.port}",
            "--dir",
            str(d),
            "--log",
            str(log),
            "--profile",
            "lab",
        ],
        env=ENV,
        cwd=TREE,
        stdout=err,
        stderr=subprocess.STDOUT,
    )
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    sizes: dict[str, int] = {}

    def sent(label: str, body: bytes) -> bytes:
        # Records are matched to requests by body size, so every size must be unique.
        assert len(body) not in sizes.values(), f"{label}: body size {len(body)} not unique"
        sizes[label] = len(body)
        return body

    # Controls: a plain request flows, unchanged, with the NRIC in it; the path keeps no prefix (ADR-0006).
    plain = sent("plain", msg(f"my NRIC is {NRIC}", pad=100))
    st, _ = post(port, "/v1/messages", plain)
    ok = st == 200 and up.seen and up.seen[-1][3] == plain and up.seen[-1][1] == "/v1/messages"
    check("F04.ctl.identity-body-forwarded", "CTRL", bool(ok), f"status {st}")
    check("F05.ctl.planted-value-reached-upstream", "CTRL", bool(up.seen) and NRIC.encode() in up.seen[-1][3])

    # F-04: a gzip body is forwarded as sent, under its own label; the observer still sees inside it.
    gz = sent("gzip", gzip.compress(msg(f"gzip NRIC {NRIC}", pad=200)))
    n = len(up.seen)
    st, _ = post(port, "/v1/messages", gz, {"Content-Encoding": "gzip"})
    got = up.seen[n][3] if len(up.seen) > n else b""
    check(
        "F04.fix.gzip-forwarded-byte-exact",
        "FIX",
        st == 200 and got == gz,
        f"status {st}, sent {len(gz)} B, upstream got {len(got)} B",
    )
    bomb = sent("bomb", gzip.compress(bytes(100 << 20)))
    n = len(up.seen)
    st, _ = post(port, "/v1/messages", bomb, {"Content-Encoding": "gzip"})
    check(
        "F04.fix.bomb-forwarded-as-sent",
        "FIX",
        st == 200 and len(up.seen) > n and up.seen[n][3] == bomb,
        f"status {st}",
    )

    # F-05: malformed requests carrying the value; responses must not echo it.
    malformed = {
        "nul-in-header": f"GET /a HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Note: {NRIC}\x00\r\n\r\n",
        "bad-chunk-size": f"POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n\r\n{NRIC}\r\n",
        "bad-request-line": f"GET /{NRIC} HTTP/1.1 extra\r\nHost: 127.0.0.1\r\n\r\n",
        "obs-fold": f"GET /a HTTP/1.1\r\nHost: 127.0.0.1\r\nX-A: 1\r\n  {NRIC}\r\n\r\n",
    }
    replies = {k: raw(port, v.encode("latin-1")) for k, v in malformed.items()}
    check(
        "F05.ctl.parser-error-path-reached",
        "CTRL",
        all(re.match(rb"HTTP/1\.[01] 400 ", r) for r in replies.values()),
        ", ".join(f"{k}:{r[9:12].decode() or '-'}" for k, r in replies.items()),
    )
    echo = [k for k, r in replies.items() if NRIC.encode() in r]
    check("F05.fix.no-value-in-error-bodies", "FIX", echo == [], f"echoed by: {echo}")
    post(port, f"/v1/messages/{NRIC}?ref={NRIC}", sent("path", msg("path probe", pad=300)))

    # F-06: requests that used to vanish from observation.
    post(port, "/v1/messages", sent("long-model", msg(f"id {NRIC}", model="x" * 20000, pad=400)))
    deep = sent(
        "deep", b'{"messages":[{"role":"user","content":"x"}],"pad":' + b"[" * 100000 + b"]" * 100000 + b"}"
    )
    post(port, "/v1/messages", deep)
    post(port, "/v1/messages", sent("model-nric", msg("hello", model=f"m-{NRIC}", pad=500)))
    time.sleep(1.0)
    os.chmod(log, 0o400)
    post(port, "/v1/messages", sent("unwritable", msg("while read-only", pad=600)))
    time.sleep(1.0)
    os.chmod(log, 0o600)
    post(port, "/v1/messages", sent("after-unwritable", msg("after", pad=700)))

    # F-08: listener refuses foreign Host / Origin before anything is forwarded.
    n = len(up.seen)
    st_host, _ = post(port, "/v1/messages", msg("rebind"), host="evil.example:8787")
    st_origin, _ = post(port, "/v1/messages", msg("cors"), {"Origin": "http://evil.example"})
    no_host = raw(port, b"GET /v1/models HTTP/1.0\r\n\r\n")
    check("F08.fix.foreign-host-refused", "FIX", st_host == 421, f"status {st_host}")
    check("F08.fix.foreign-origin-refused", "FIX", st_origin == 403, f"status {st_origin}")
    check("F08.fix.missing-host-refused", "FIX", no_host[9:12] == b"421", f"status {no_host[9:12].decode()}")
    check("F08.fix.refused-requests-not-forwarded", "FIX", len(up.seen) == n, f"{len(up.seen) - n} forwarded")
    st, _ = post(port, "/v1/messages", msg("loopback name ok"), host=f"localhost:{port}")
    check("F08.ctl.loopback-host-accepted", "CTRL", st == 200, f"status {st}")

    time.sleep(1.0)
    srv.send_signal(signal.SIGTERM)
    try:
        rc = srv.wait(20)
    except subprocess.TimeoutExpired:
        srv.kill()
        rc = -9
    err.close()
    stderr = (TMP / "serve.err").read_text(errors="replace")
    check(
        "F05.fix.no-value-in-serve-output",
        "FIX",
        NRIC not in stderr,
        f"{stderr.count(NRIC)} occurrence(s) in serve's stderr",
    )
    check("F06.ctl.serve-exits-on-sigterm", "CTRL", rc is not None and rc != -9, f"exit {rc}")

    recs = open_records(d, log)
    obs = [r for r in recs if r.get("event") == "observe"]
    by_size: dict[int, list[dict[str, Any]]] = {}
    for r in obs:
        by_size.setdefault(r.get("bytes", -1), []).append(r)

    def rec(label: str) -> dict[str, Any] | None:
        return (by_size.get(sizes[label]) or [None])[0]

    def types(r: dict[str, Any] | None) -> list[str]:
        return [x["t"] for x in (r or {}).get("new", [])]

    p = rec("plain")
    check("F06.ctl.plain-request-observed", "CTRL", p is not None and "NRIC" in types(p))
    g = rec("gzip")
    check(
        "F04.fix.gzip-body-observed-inside",
        "FIX",
        g is not None and g.get("scanned") is True and "NRIC" in types(g),
        f"record: scanned={g and g.get('scanned')}, reason={g and g.get('reason')}, types={types(g)}",
    )
    b = rec("bomb")
    check(
        "F04.fix.bomb-decoding-bounded-gap",
        "FIX",
        b is not None and b.get("reason") == "decoded_too_large",
        f"record reason={b and b.get('reason')}",
    )
    lm = rec("long-model")
    check(
        "F06.fix.oversized-model-recorded",
        "FIX",
        lm is not None and lm.get("model", "").startswith("<withheld"),
        f"record={'present' if lm else 'missing'}",
    )
    dp = rec("deep")
    check(
        "F06.fix.deep-json-recorded-as-gap",
        "FIX",
        dp is not None and dp.get("scanned") is False,
        f"reason={dp and dp.get('reason')}",
    )
    mn = rec("model-nric")
    check(
        "F06.fix.identifier-in-model-withheld",
        "FIX",
        mn is not None and NRIC not in json.dumps(mn) and mn.get("model", "").startswith("<withheld"),
        f"model={mn and mn.get('model')}",
    )
    pr = rec("path")
    check(
        "F06.fix.identifier-in-path-withheld",
        "FIX",
        pr is not None and NRIC not in json.dumps(pr) and "NRIC" in types(pr),
        f"path={pr and pr.get('path')}",
    )
    check("F06.ctl.unwritable-request-not-recorded", "CTRL", rec("unwritable") is None)
    au = rec("after-unwritable")
    check(
        "F06.fix.unrecorded-request-counted",
        "FIX",
        au is not None and au.get("failed_before") == 1,
        f"failed_before={au and au.get('failed_before')}",
    )
    stop = [r for r in recs if r.get("event") == "observe_stop"]
    check("F06.fix.shutdown-record-written", "FIX", len(stop) == 1, f"{len(stop)} observe_stop record(s)")
    check("F05.fix.no-value-in-audit-records", "FIX", NRIC not in json.dumps(recs))
    check("F11.ctl.serve-log-verifies", "CTRL", ppe("audit", "verify", "--log", str(log)).returncode == 0)


# --- F-14: committed bench data and the sdist ------------------------------------------------------------


def f14_checks() -> None:
    r = tree_py(
        "import re,subprocess\n"
        "from pathlib import Path\n"
        "from prompt_privacy.detectors.base import detect\n"
        "from prompt_privacy.core.types import EntityType as T\n"
        "from prompt_privacy.core.checksums import nric_valid, luhn_valid, iban_valid, nric_check_letter\n"
        "allowed={'S1234567D','T9119134I','M1235467X','4111111111111111','GB82WEST12345698765432','490154203237518'}\n"
        "def bad(text):\n"
        "    out=[]\n"
        "    for f in detect(text):\n"
        "        v=re.sub(r'[\\s-]','',f.value).upper()\n"
        "        if ((f.type is T.NRIC and nric_valid(v)) or (f.type is T.CARD and luhn_valid(v)) or (f.type is T.IBAN and iban_valid(v))) and v not in allowed: out.append(f.type.value)\n"
        "    return out\n"
        "planted='S7654321'+nric_check_letter('S','7654321')\n"
        "print(bad('id '+planted+' here'))\n"
        "files=subprocess.run(['git','ls-files','bench/*'],capture_output=True,text=True).stdout.split()\n"
        "print(sum(len(bad(Path(p).read_text(errors='replace'))) for p in files if Path(p).suffix in ('.txt','.json','.jsonl','.log','.md')))\n"
    )
    lines = r.stdout.split("\n")
    check(
        "F14.ctl.scanner-flags-generated-valid-id",
        "CTRL",
        lines[:1] == ["['NRIC']"],
        lines[0] if lines else r.stderr[-200:],
    )
    check(
        "F14.fix.no-generated-valid-ids-committed",
        "FIX",
        lines[1:2] == ["0"],
        f"{lines[1] if len(lines) > 1 else '?'} found",
    )
    out = TMP / "sdist"
    b = subprocess.run(
        [str(Path.home() / "ai-env/bin/uv"), "build", "--sdist", "-o", str(out), str(TREE)],
        capture_output=True,
        text=True,
        timeout=600,
    )
    names = []
    if b.returncode == 0:
        tar = next(out.glob("*.tar.gz"))
        names = subprocess.run(["tar", "tzf", str(tar)], capture_output=True, text=True).stdout.split()
    check(
        "F14.ctl.sdist-builds-with-sources",
        "CTRL",
        any(n.endswith("src/prompt_privacy/proxy/app.py") for n in names),
    )
    leaked = [n for n in names if "/bench/results/" in n or re.search(r"/bench/review-[^/]+/results/", n)]
    check(
        "F14.fix.sdist-excludes-bench-results",
        "FIX",
        names != [] and leaked == [],
        f"{len(leaked)} result file(s) in sdist",
    )


def main() -> int:
    print(f"tree: {TREE}")
    head = subprocess.run(["git", "-C", str(TREE), "log", "--oneline", "-1"], capture_output=True, text=True)
    print(f"commit: {head.stdout.strip()}\n")
    docs_checks()
    audit_checks()
    proxy_checks()
    f14_checks()
    by_kind: dict[str, list[bool]] = {}
    for _, kind, ok, _ in RESULTS:
        by_kind.setdefault(kind, []).append(ok)
    print("\n" + "  ".join(f"{k}: {sum(v)}/{len(v)} pass" for k, v in sorted(by_kind.items())))
    shutil.rmtree(TMP, ignore_errors=True)
    return 0 if all(ok for _, _, ok, _ in RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())

"""Review probes (synthetic data only): engine, surrogates, audit, detection."""
import json, random, tempfile, re
from pathlib import Path
from prompt_privacy.core.engine import Engine, Message
from prompt_privacy.core.keys import TokenKey
from prompt_privacy.core.types import EntityType as T
from prompt_privacy.core.normalise import norm
from prompt_privacy.core import checksums
from prompt_privacy.detectors.base import detect, Dictionary
from prompt_privacy.audit.keys import AuditKeyPair, dev_token_keypair
from prompt_privacy.audit.log import AuditLog, verify_chain, open_log, read_envelopes
from prompt_privacy.audit.envelope import seal, open_envelope

def out(k, v): print(f"{k:58} {v}")
K = TokenKey(bytes(range(32)))

# P10a R4: restore into JSON (PEM secret)
pem = "-----BEGIN PRIVATE KEY-----\nMIIBVwIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAexample\n-----END PRIVATE KEY-----"
eng = Engine(K)
res = eng.mask([Message("user", "deploy with key:\n" + pem)], "c")
sur = next(e.surrogate.canonical for e in res.vault.entries.values() if e.etype is T.SECRET)
args = json.dumps({"key": sur})  # provider emits tool args with the surrogate JSON-escaped
restored = eng.restore(args, res.vault).text
try:
    json.loads(restored); ok = "valid JSON"
except Exception as e:
    ok = f"INVALID JSON ({type(e).__name__})"
out("P10a R4 restore PEM surrogate inside JSON tool args", f"{ok}; restored={eng.restore(args, res.vault).restored}")

# P10b e-mail surrogate with upper-case domain
res = eng.mask([Message("user", "mail jane.tan@acme-corp.test")], "c")
e = next(x for x in res.vault.entries.values() if x.etype is T.EMAIL)
loc, dom = e.surrogate.canonical.split("@")
r = eng.restore(f"Write to {loc}@{dom.upper()}", res.vault)
out("P10b e-mail domain upper-case restored (ADR-0008 says yes)", r.restored == 1)

# P10c name component ambiguity: surrogate given name used as a generic word elsewhere
eng2 = Engine(K, Dictionary([("Jane Tan", T.PERSON)]))
res = eng2.mask([Message("user", "I'm Jane Tan.")], "c")
p = next(x for x in res.vault.entries.values() if x.etype is T.PERSON)
given_sur = p.surrogate.components[0][1]
reply = f"For example, {given_sur} is a common name in many places."
r = eng2.restore(reply, res.vault)
out("P10c unrelated use of surrogate given name restored to real", f"{r.text!r}")

# P10d stability when an unrestored surrogate text appears in history (vault probing on conversation text)
res1 = eng.mask([Message("user", "my NRIC is S1234567D")], "c9")
s1 = next(x for x in res1.vault.entries.values() if x.etype is T.NRIC).surrogate.canonical
# model reformats in a way restore does not catch (e.g. spelled with slashes) -> history keeps the surrogate literally
hist = [Message("user", "my NRIC is S1234567D"), Message("assistant", f"Noted {s1}."), Message("user", "and again S1234567D")]
res2 = eng.mask(hist, "c9")
s2 = next(x for x in res2.vault.entries.values() if x.etype is T.NRIC).surrogate.canonical
out("P10d surrogate stable when surrogate literal is in history", f"{s1 == s2} ({s1} vs {s2})")
out("P10d   turn-1 user text masks identically on turn 2", res1.messages[0].text == res2.messages[0].text)

# P10e phone normalisation: +65 vs local form of the same SG number
a, b = norm(T.PHONE, "+65 9123 4567"), norm(T.PHONE, "9123 4567")
out("P10e same SG phone with/without +65 normalises equal (ADR-0002: E.164)", f"{a == b} ({a} vs {b})")

# P15 checksum robustness on non-ASCII digits
for f, v in (("nric_valid", "S²234567D"), ("luhn_valid", "41²")):
    try:
        out(f"P15 {f}({v!r})", getattr(checksums, f)(v))
    except Exception as ex:
        out(f"P15 {f}({v!r})", f"RAISES {type(ex).__name__}")

# P16 card false positives on random 16-digit numbers (no IIN check)
rng = random.Random(1)
nums = ["".join(str(rng.randint(0, 9)) for _ in range(16)) for _ in range(20000)]
fp = sum(1 for n in nums if any(f.type is T.CARD for f in detect(f"tracking id {n} shipped")))
out("P16 random 16-digit IDs detected as CARD", f"{fp}/20000 = {fp/200:.2f}%")

# P17 evasions vs ADR-0005 Stage 0 design
cases = {
    "plain NRIC": "id S1234567D",
    "zero-width NRIC": "id S123​4567D",
    "full-width NRIC": "id Ｓ１２３４５６７Ｄ",
    "Cyrillic S homoglyph NRIC": "id Ѕ1234567D",
    "spaced digits NRIC": "id S 1 2 3 4 5 6 7 D",
    "dashed NRIC S-1234567-D": "id S-1234567-D",
    "percent-encoded email": "q=jane.tan%40acme-corp.test",
    "HTML entity email": "jane.tan&#64;acme-corp.test",
    "base64 NRIC": "id UzEyMzQ1NjdE",
    "split NRIC": "first S123 then 4567D",
    "email in URL userinfo": "https://jane.tan@acme-corp.test/x",
    "card with dots": "card 4111.1111.1111.1111",
    "card mixed separators": "card 4111 1111-1111 1111",
    "IBAN lowercase spaced": "acct gb82 west 1234 5698 7654 32",
    "secret in URL query": "https://api.example.com/x?api_key=sk-proj-abcdefghijklmnopqrstuvwxyz123456",
    "AWS key lowercase": "akiaiosfodnn7example",
    "email with + tag": "jane.tan+promo@acme-corp.test",
    "IPv4-mapped IPv6": "::ffff:192.0.2.10",
    "IPv6 compressed": "2001:db8::1",
    "SG phone no context": "9123 4567",
    "SG phone +65": "+65 9123 4567",
    "NANP no context": "(415) 555-0123",
}
for name, text in cases.items():
    fs = detect(text)
    out(f"P17 {name}", [f"{f.type.value}:{f.value!r}" for f in fs] or "MISSED")

# P7 padding buckets per event type / finding count
with tempfile.TemporaryDirectory() as d:
    m, u = AuditKeyPair.generate(), AuditKeyPair.generate()
    log = AuditLog(Path(d) / "a.jsonl", m.public, u.public, "lab")
    log.append({"event": "digest_key", "kid": "0" * 16, "k_dig": "ab" * 32})
    base = {"event": "observe", "flow": "prompt", "zone": "cloud", "req_id": "0" * 16, "method": "POST",
            "path": "/v1/messages", "conv": "c" * 32, "bytes": 1234, "ts": 1760000000, "norm_v": 1, "kid": "0" * 16,
            "scanned": True, "model": "claude-x", "skipped_blocks": 0, "findings_total": 0, "part": 0, "parts": 1}
    item = {"t": "EMAIL", "c": "direct_identifier", "det": "rules.patterns", "d": "f" * 32}
    for n in (0, 1, 5, 9, 10, 40, 100):
        log.append({**base, "findings_total": n, "new": [item] * n})
    sizes = [(json.loads(l).get("seq"), len(json.loads(l)["ct"])) for l in (Path(d) / "a.jsonl").read_text().splitlines()]
    out("P7 ct length: digest_key, observe n=0,1,5,9,10,40,100", [s for _, s in sizes])

# P11 swap HPKE wraps between two records -> must fail
with tempfile.TemporaryDirectory() as d:
    m, u = AuditKeyPair.generate(), AuditKeyPair.generate()
    log = AuditLog(Path(d) / "a.jsonl", m.public, u.public, "lab")
    log.append({"event": "x", "n": 1}); log.append({"event": "x", "n": 2})
    e1, e2 = list(read_envelopes(Path(d) / "a.jsonl"))
    try:
        open_envelope({**e2, "w_m": e1["w_m"]}, m, u); r = "OPENED (bad)"
    except Exception as ex:
        r = f"refused ({type(ex).__name__})"
    out("P11 machine wrap moved to another record", r)

# P12/P13 forge & truncate with public keys only
with tempfile.TemporaryDirectory() as d:
    m, u = AuditKeyPair.generate(), AuditKeyPair.generate()
    p = Path(d) / "a.jsonl"
    log = AuditLog(p, m.public, u.public, "lab")
    for i in range(5):
        log.append({"event": "observe", "i": i})
    lines = p.read_text().splitlines()
    p.write_text("\n".join(lines[:3]) + "\n")
    out("P13 tail truncated (5 -> 3 records) passes verify_chain", verify_chain(p).ok)
    p.unlink()
    forged = AuditLog(p, m.public, u.public, "lab")  # attacker holds only the PUBLIC keys
    forged.append({"event": "observe", "note": "fabricated history"})
    out("P12 log rewritten from scratch with public keys passes verify", verify_chain(p).ok)
    out("P12   ...and opens as genuine with both parts", next(open_log(p, m, u))["note"])

# P8 two writers on one log
with tempfile.TemporaryDirectory() as d:
    m, u = AuditKeyPair.generate(), AuditKeyPair.generate()
    p = Path(d) / "a.jsonl"
    w1 = AuditLog(p, m.public, u.public, "lab"); w2 = AuditLog(p, m.public, u.public, "lab")
    for i in range(3):
        w1.append({"event": "a", "i": i}); w2.append({"event": "b", "i": i})
    v = verify_chain(p)
    out("P8 two concurrent writers -> chain verifies", f"{v.ok} {v.error}")

# P9 crash mid-append (partial last line)
with tempfile.TemporaryDirectory() as d:
    m, u = AuditKeyPair.generate(), AuditKeyPair.generate()
    p = Path(d) / "a.jsonl"
    log = AuditLog(p, m.public, u.public, "lab"); log.append({"event": "a"})
    with p.open("a") as f:
        f.write('{"v":2,"seq":1,"prev":"ab')  # torn write
    for what, fn in (("verify_chain", lambda: verify_chain(p)), ("AuditLog reopen", lambda: AuditLog(p, m.public, u.public, "lab"))):
        try:
            r = fn(); out(f"P9 torn last line: {what}", getattr(r, "ok", "opened"))
        except Exception as ex:
            out(f"P9 torn last line: {what}", f"RAISES {type(ex).__name__}")

"""Targeted mutation testing: inject one security-relevant bug at a time into a copy; run the suite."""
import shutil, subprocess, sys, os, time, pathlib
REPO = pathlib.Path(__file__).resolve().parents[3]  # repo root
WORK = pathlib.Path(sys.argv[1]); PY = sys.argv[2]
M = [  # (id, file, old, new, what the bug means)
 ("M01", "core/checksums.py", "return _M_LETTERS[10 - total % 11]", "return _M_LETTERS[total % 11]", "M-series FIN check letter wrong"),
 ("M02", "core/checksums.py", "        if i % 2 == 0:\n            d *= 2", "        if i % 2 == 1:\n            d *= 2", "Luhn doubles the wrong digits"),
 ("M03", "core/checksums.py", "return _iban_numeric(v[4:] + v[:4]) % 97 == 1", "return _iban_numeric(v[4:] + v[:4]) % 97 in (0, 1)", "IBAN accepts mod-97 == 0"),
 ("M04", "detectors/patterns.py", "if not strict or nric_valid(re.sub(r\"[ -]\", \"\", m.group())):", "if True:", "NRIC checksum not required"),
 ("M05", "detectors/patterns.py", "if 13 <= len(d) <= 19 and (luhn_valid(d) if strict else True):", "if 13 <= len(d) <= 19:", "card Luhn not required"),
 ("M06", "core/shadow.py", "        if ch in _INVISIBLE:\n            continue", "        if ch in _INVISIBLE:\n            pass", "zero-width/bidi no longer stripped"),
 ("M07", "detectors/base.py", "    EntityType.SECRET: 0,", "    EntityType.SECRET: 9,", "secrets lose overlap priority"),
 ("M08", "core/engine.py", "fs = [] if m.role == \"assistant\" else detect(m.text, self.dictionary)", "fs = detect(m.text, self.dictionary)", "assistant history freshly detected (R3)"),
 ("M09", "core/engine.py", "if tok is not None and m.group(2).upper() == tok.etype.value:", "if tok is not None:", "token TYPE label not checked (R2)"),
 ("M10", "core/vault.py", "if ckey in self._by_canonical or ckey in self._originals or s.canonical in self._text:", "if ckey in self._by_canonical:", "surrogate may equal a real value"),
 ("M11", "core/surrogates.py", "letters = [c for c in \"ABCDEFGHIJKLMNPQRTUWXZ\" if c != valid]", "letters = [c for c in \"ABCDEFGHIJKLMNPQRTUWXZ\"]", "NRIC surrogate may be valid (G2)"),
 ("M12", "core/surrogates.py", "return body + str((valid + r.randint(1, 9)) % 10)", "return body + str((valid + r.randint(0, 9)) % 10)", "card surrogate may pass Luhn (G2)"),
 ("M13", "core/surrogates.py", "local = f\"{area}5550{r.randint(100, 199)}\"", "local = f\"{area}555{r.randint(1000, 9999)}\"", "NANP surrogate outside 555-01xx (G1)"),
 ("M14", "audit/envelope.py", "ct = AESGCM(dek).encrypt(nonce, _pad(canonical(record)), hb)", "ct = AESGCM(dek).encrypt(nonce, _pad(canonical(record)), None)", "header not bound to ciphertext (enc side)"),
 ("M15", "audit/envelope.py", "s2 = bytes(a ^ b for a, b in zip(dek, s1, strict=True))", "s2 = dek", "token share alone = DEK (2-of-2 broken)"),
 ("M16", "audit/log.py", "        if env.get(\"prev\") != prev:\n            return VerifyResult(False, n, f\"chain broken at record {n}\")", "", "chain linkage not verified"),
 ("M17", "audit/log.py", "if pk_token.kid == DEV_TOKEN_KID and profile != \"lab\":", "if False:", "dev token accepted in any profile"),
 ("M18", "audit/keys.py", "    if path.stat().st_mode & 0o077:\n        raise PermissionError", "    if False:\n        raise PermissionError", "machine key perms not enforced"),
 ("M19", "core/keys.py", "            if path.stat().st_mode & 0o077:", "            if False:", "token key perms not enforced"),
 ("M20", "proxy/observe.py", "            if s.digest not in seen:", "            if True:", "no per-conversation dedup"),
 ("M21", "proxy/observe.py", "msg = b\"ppe/obs/v1\" + lp(etype) + lp(value_norm)", "msg = b\"ppe/obs/v1\" + lp(value_norm)", "digest not bound to type"),
 ("M22", "proxy/app.py", "_REQ_DROP = _HOP | {\"host\", \"content-length\"}", "_REQ_DROP = {\"host\", \"content-length\"}", "hop-by-hop request headers forwarded"),
 ("M23", "proxy/app.py", "        ok = ipaddress.ip_address(host.strip(\"[]\")).is_loopback", "        ok = True", "listen on any address"),
 ("M24", "proxy/app.py", "        if u.scheme == \"http\" and self.upstream_zone != \"loopback\":", "        if False:", "cleartext http to cloud upstream"),
 ("M25", "proxy/app.py", "        if cls.__module__ != \"aiohttp._http_parser\":", "        if False:", "pure-Python parser accepted"),
 ("M26", "proxy/app.py", "    if any(seg in (\".\", \"..\") for seg in request.path.split(\"/\")):\n        return None", "", "dot segments forwarded"),
 ("M27", "proxy/app.py", "            auto_decompress=False,", "            auto_decompress=True,", "responses decompressed in transit"),
 ("M28", "core/engine.py", "for s, e, rep in sorted(edits, key=lambda x: -x[0]):", "for s, e, rep in sorted(edits, key=lambda x: x[0]):", "splice order wrong (offsets corrupt)"),
 ("M29", "core/normalise.py", "return f\"{local}@{domain.lower()}\"", "return f\"{local}@{domain}\"", "email domain case not normalised"),
 ("M30", "detectors/patterns.py", "        if i and blocked[i - 1][1] > m.start():\n            continue", "", "dates no longer block phones"),
 ("M31", "proxy/observe.py", "        if isinstance(m, dict) and m.get(\"role\") != \"assistant\":", "        if isinstance(m, dict):", "assistant turns scanned as prompt"),
 ("M32", "audit/envelope.py", "BUCKETS = (256, 1024, 4096, 16384)", "BUCKETS = (64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384)", "finer padding buckets (more size leakage)"),
]
results = []
ONLY = set(sys.argv[3:])  # optional mutant ids to run, e.g. M08 M30
for mid, rel, old, new, what in M:
    if ONLY and mid not in ONLY:
        continue
    if WORK.exists(): shutil.rmtree(WORK)
    shutil.copytree(REPO / "src", WORK / "src"); shutil.copytree(REPO / "tests", WORK / "tests")
    for f in ("pyproject.toml",): shutil.copy(REPO / f, WORK / f)
    for d in ("schemas", "policies"): shutil.copytree(REPO / d, WORK / d)
    p = WORK / "src/prompt_privacy" / rel
    src = p.read_text()
    if src.count(old) != 1:
        results.append((mid, "NOT-APPLIED", what)); print(mid, "NOT APPLIED", flush=True); continue
    p.write_text(src.replace(old, new))
    env = {**os.environ, "PYTHONPATH": str(WORK / "src")}
    t0 = time.time()
    r = subprocess.run([PY, "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider", "tests",
                        # repo-level claims call `git ls-files`; the copy is not a git checkout
                        "--deselect", "tests/conformance/test_claims_repo.py"], cwd=WORK, env=env, capture_output=True, text=True)
    killed = r.returncode != 0
    first_fail = next((l for l in r.stdout.splitlines() if l.startswith("FAILED") or "Error" in l[:40]), "")
    results.append((mid, "killed" if killed else "SURVIVED", what))
    print(f"{mid} {'killed  ' if killed else 'SURVIVED'} {time.time()-t0:5.1f}s  {what:45} {first_fail[:90]}", flush=True)
s = sum(1 for _, k, _ in results if k == "killed"); n = sum(1 for _, k, _ in results if k != "NOT-APPLIED")
print(f"\nmutation score: {s}/{n} killed")

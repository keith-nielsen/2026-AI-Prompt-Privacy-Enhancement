"""Dogfood: run PPE's Stage 1 detectors over every tracked file; summarise what looks non-synthetic."""
import subprocess, collections, ipaddress
from prompt_privacy.detectors.base import detect
from prompt_privacy.core.types import EntityType as T

RESERVED_DOMAINS = (".example", ".test", ".invalid", "example.com", "example.net", "example.org", "localhost")
files = subprocess.run(["git", "ls-files"], capture_output=True, text=True, check=True).stdout.split()
by = collections.Counter(); hits = collections.defaultdict(list)
for f in files:
    if f.endswith((".pdf", ".png")):
        continue
    try:
        text = open(f, encoding="utf-8").read()
    except Exception:
        continue
    for x in detect(text):
        v = x.value
        synthetic = (
            (x.type is T.EMAIL and v.lower().split("@")[-1].endswith(RESERVED_DOMAINS))
            or (x.type is T.IPV4 and (ipaddress.ip_address(v).is_private or ipaddress.ip_address(v) in ipaddress.ip_network("192.0.2.0/24")
                                      or ipaddress.ip_address(v) in ipaddress.ip_network("198.51.100.0/24")
                                      or ipaddress.ip_address(v) in ipaddress.ip_network("203.0.113.0/24") or ipaddress.ip_address(v).is_loopback))
            or (x.type is T.IPV6 and v.lower().startswith(("2001:db8", "::1", "::ffff")))
            or (x.type is T.PHONE and ("555" in v or "7700 900" in v.replace("-", " ")))
            or (x.type is T.SECRET and "EXAMPLE" in v)
        )
        key = (x.type.value, "synthetic-range" if synthetic else "NOT a reserved range")
        by[key] += 1
        if not synthetic:
            hits[(x.type.value, f)].append(v)
for k, n in sorted(by.items()):
    print(f"{k[0]:7} {k[1]:22} {n}")
print("\nfiles with non-reserved-range findings (type, file, count, sample preview):")
for (t, f), vs in sorted(hits.items(), key=lambda kv: -len(kv[1])):
    s = vs[0]
    print(f"  {t:7} {f:62} {len(vs):4}  e.g. {s[:3]}…{s[-2:]} ({len(s)} ch)")

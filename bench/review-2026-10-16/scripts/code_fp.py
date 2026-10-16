"""False positives of Stage 1 on source code (the main payload of coding-agent prompts)."""
import collections, pathlib, sys, time
from prompt_privacy.detectors.base import detect
from prompt_privacy.core.types import EntityType as T

root = pathlib.Path(sys.argv[1])
pkgs = ["aiohttp", "cryptography", "hypothesis", "yaml", "jsonschema", "multidict", "yarl", "argon2", "attr", "referencing"]
files = [f for p in pkgs for f in (root / p).rglob("*.py")]
total = 0; counts = collections.Counter(); samples = collections.defaultdict(list); t0 = time.perf_counter()
for f in files:
    s = f.read_text(errors="replace"); total += len(s.encode())
    for x in detect(s):
        counts[x.type.value] += 1
        if len(samples[x.type.value]) < 6:
            samples[x.type.value].append(x.value[:40].replace("\n", " "))
mb = total / 1e6
print(f"{len(files)} files, {mb:.1f} MB of third-party Python, {time.perf_counter()-t0:.1f} s")
for t, n in counts.most_common():
    print(f"  {t:7} {n:6}  = {n/mb:7.1f} per MB   e.g. {samples[t]}")

snips = {
    "rust": "use std::io::{self, Read};\nfn main() { let v: Vec<u8> = std::vec::Vec::new(); }",
    "cpp": "std::string s = ns::util::join(parts, \"::\"); auto it = map.find(key);",
    "php": "return self::$instance ?? static::create();",
    "css": "a::before { content: ''; } p::first-line {}",
    "ruby": "Foo::Bar::Baz.new",
    "py-classifier": "Development Status :: 4 - Beta",
    "py-token-var": "token = get_token(request)\npassword = form.cleaned_data['password']\nAPI_KEY = os.environ['API_KEY']",
    "log line": "2026-10-16 03:12:47,123 INFO pid=3712 took 91234567 ns",
    "git sha": "commit 3ec6e7266a0c58846e64b7d5172077fb00717708",
    "uuid": "id 550e8400-e29b-41d4-a716-446655440000",
    "imei": "IMEI 490154203237518",
}
print()
for k, s in snips.items():
    print(f"  {k:14} -> {[f'{x.type.value}:{x.value}' for x in detect(s)]}")

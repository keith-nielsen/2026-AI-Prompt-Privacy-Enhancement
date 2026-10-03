"""`ppe` command line (phase 1): scan, mask, corpus, bench, explain, verify, audit."""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path
from typing import Any

from prompt_privacy import __version__, knobs, policy
from prompt_privacy.core.types import EntityType


def _read(source: str) -> str:
    return sys.stdin.read() if source == "-" else Path(source).read_text()


def _dictionary(pol: dict[str, Any]):  # type: ignore[no-untyped-def]
    from prompt_privacy.detectors.base import Dictionary

    entries = (pol.get("detection") or {}).get("dictionary") or []
    return Dictionary((e["term"], EntityType(e["type"])) for e in entries) if entries else None


def _preview(value: str) -> str:
    """Never print the value itself (invariant 1): first/last character and length only."""
    v = value.replace("\n", " ")
    return f"{v[0]}…{v[-1]} ({len(v)} chars)" if len(v) > 2 else f"… ({len(v)} chars)"


def cmd_scan(a: argparse.Namespace) -> int:
    from prompt_privacy.detectors.base import detect

    pol = policy.load(a.policy)
    text = _read(a.file)
    phone_ctx = (pol.get("detection") or {}).get("phone_context") == "required"
    findings = detect(text, _dictionary(pol), phone_context=phone_ctx)
    for f in findings:
        print(f"{f.start:>7}-{f.end:<7} {f.type.value:<7} {f.subtype or f.detector:<22} {_preview(f.value)}")
    print(f"{len(findings)} finding(s)", file=sys.stderr)
    return 1 if findings else 0


def cmd_mask(a: argparse.Namespace) -> int:
    from prompt_privacy.core.engine import Engine, Message
    from prompt_privacy.core.keys import TokenKey

    pol = policy.load(a.policy)
    key = TokenKey.load_or_create(Path(a.key_file))
    form = (pol.get("swap") or {}).get("form", "surrogate")
    res = Engine(key, _dictionary(pol), form).mask([Message("user", _read(a.file))], a.conversation)
    sys.stdout.write(res.messages[0].text)
    print(f"\n[{len(res.findings)} value(s) swapped, form={form}, key {key.kid}]", file=sys.stderr)
    return 0


def cmd_corpus(a: argparse.Namespace) -> int:
    from prompt_privacy.corpus.generator import write_jsonl

    n = write_jsonl(Path(a.out), a.n, a.seed)
    print(f"wrote {n} synthetic items to {a.out} (seed {a.seed})")
    return 0


def cmd_bench(a: argparse.Namespace) -> int:
    from prompt_privacy import bench

    print(bench.run(a.n, a.seed, a.phone_context == "required").table())
    return 0


def cmd_explain(a: argparse.Namespace) -> int:
    print(knobs.explain(policy.load(a.policy)))
    return 0


def cmd_verify(a: argparse.Namespace) -> int:
    from prompt_privacy.selftest import run_all

    results = run_all(n=a.n)
    for name, ok, detail in results:
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  — {detail}" if detail else ""))
    failed = sum(not ok for _, ok, _ in results)
    print(f"\n{len(results) - failed}/{len(results)} checks passed")
    return 1 if failed else 0


def _token_part(a: argparse.Namespace, create: bool = False):  # type: ignore[no-untyped-def]
    """The token part: the "1234" dev stand-in, or a passphrase + per-installation salt (not secret)."""
    import secrets

    from prompt_privacy.audit.keys import AuditKeyPair, dev_token_keypair

    if a.dev_token:
        return dev_token_keypair()
    salt_file = Path(a.dir) / "token.salt"
    if create:
        salt_file.write_bytes(secrets.token_bytes(16))
    return AuditKeyPair.from_passphrase(getpass.getpass("token passphrase: "), salt_file.read_bytes())


def cmd_audit_keygen(a: argparse.Namespace) -> int:
    from prompt_privacy.audit.keys import AuditKeyPair, write_private

    d = Path(a.dir)
    m = AuditKeyPair.generate()
    write_private(d / "machine.key", m)
    (d / "machine.pub").write_bytes(m.public.raw)
    token = _token_part(a, create=True)
    (d / "token.pub").write_bytes(token.public.raw)
    print(f"machine key {m.public.kid} -> {d / 'machine.key'} (0600)")
    print(f"token public key {token.public.kid} -> {d / 'token.pub'}")
    print(
        "the token's private part is NOT stored: it is re-derived from the passphrase when opening the audit"
    )
    return 0


def cmd_audit_append(a: argparse.Namespace) -> int:
    from prompt_privacy.audit.keys import AuditPublicKey
    from prompt_privacy.audit.log import AuditLog

    d = Path(a.dir)
    log = AuditLog(
        Path(a.log),
        AuditPublicKey((d / "machine.pub").read_bytes()),
        AuditPublicKey((d / "token.pub").read_bytes()),
        a.profile,
    )
    env = log.append(json.loads(a.record))
    print(f"appended seq {env['seq']}")
    return 0


def cmd_audit_verify(a: argparse.Namespace) -> int:
    from prompt_privacy.audit.log import verify_chain

    r = verify_chain(Path(a.log))
    print(f"{'OK' if r.ok else 'BROKEN'}: {r.count} record(s) {r.error}")
    return 0 if r.ok else 1


def cmd_audit_open(a: argparse.Namespace) -> int:
    from prompt_privacy.audit.keys import read_private
    from prompt_privacy.audit.log import open_log

    machine = read_private(Path(a.machine_key))
    for rec in open_log(Path(a.log), machine, _token_part(a)):
        print(json.dumps(rec, ensure_ascii=False))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ppe", description="Prompt Privacy Enhancement")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="offline detection report (values are never printed)")
    s.add_argument("file", nargs="?", default="-")
    s.add_argument("--policy", type=Path)
    s.set_defaults(fn=cmd_scan)

    s = sub.add_parser("mask", help="swap detected values for surrogates (demo of the engine)")
    s.add_argument("file", nargs="?", default="-")
    s.add_argument("--policy", type=Path)
    s.add_argument("--conversation", default="cli")
    s.add_argument("--key-file", default=".ppe-dev/token.key")
    s.set_defaults(fn=cmd_mask)

    s = sub.add_parser("corpus", help="generate the synthetic labelled corpus (JSONL)")
    s.add_argument("--n", type=int, default=2000)
    s.add_argument("--seed", type=int, default=20261002)
    s.add_argument("--out", default="corpus-out/corpus.jsonl")
    s.set_defaults(fn=cmd_corpus)

    s = sub.add_parser("bench", help="detection rates per type on the synthetic corpus")
    s.add_argument("--n", type=int, default=2000)
    s.add_argument("--seed", type=int, default=20261002)
    s.add_argument("--phone-context", choices=("optional", "required"), default="optional")
    s.set_defaults(fn=cmd_bench)

    s = sub.add_parser("explain", help="what your configuration protects and gives up")
    s.add_argument("--policy", type=Path)
    s.set_defaults(fn=cmd_explain)

    s = sub.add_parser("verify", help="run the conformance self-tests on synthetic data")
    s.add_argument("--n", type=int, default=300)
    s.set_defaults(fn=cmd_verify)

    au = sub.add_parser("audit", help="sealed audit: keys, append, verify, open").add_subparsers(
        dest="acmd", required=True
    )
    s = au.add_parser("keygen")
    s.add_argument("--dir", default=".ppe-dev/audit")
    s.add_argument("--dev-token", action="store_true", help='use the "1234" development token stand-in')
    s.set_defaults(fn=cmd_audit_keygen)
    s = au.add_parser("append")
    s.add_argument("record", help="JSON object")
    s.add_argument("--dir", default=".ppe-dev/audit")
    s.add_argument("--log", default=".ppe-dev/audit/audit.jsonl")
    s.add_argument("--profile", default="lab")
    s.set_defaults(fn=cmd_audit_append)
    s = au.add_parser("verify")
    s.add_argument("--log", default=".ppe-dev/audit/audit.jsonl")
    s.set_defaults(fn=cmd_audit_verify)
    s = au.add_parser("open", help="audit-grade decrypter: needs BOTH parts")
    s.add_argument("--dir", default=".ppe-dev/audit")
    s.add_argument("--log", default=".ppe-dev/audit/audit.jsonl")
    s.add_argument("--machine-key", default=".ppe-dev/audit/machine.key")
    s.add_argument("--dev-token", action="store_true")
    s.set_defaults(fn=cmd_audit_open)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    rc: int = args.fn(args)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())

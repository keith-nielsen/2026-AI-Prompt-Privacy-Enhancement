"""`ppe` command line: scan, mask, corpus, bench, evaluate, explain, verify, audit, serve (shadow mode)."""

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


def cmd_evaluate_list(a: argparse.Namespace) -> int:
    from prompt_privacy.evaluation.datasets import DATASETS

    for ds in DATASETS.values():
        print(f"{ds.name:<14} {ds.repo} @ {ds.revision[:12]}  {ds.licence}  splits: {', '.join(ds.splits)}")
    return 0


def cmd_evaluate_fetch(a: argparse.Namespace) -> int:
    from prompt_privacy.evaluation.datasets import DATASETS, fetch

    ds = DATASETS[a.dataset]
    if ds.source != "huggingface":
        print(
            f"refused: {ds.name} is built by the dataset's own script, not fetched by PPE; "
            "see bench/harness/build_creddata.sh"
        )
        return 2
    a.split = a.split or next(iter(ds.splits))
    path = fetch(ds, Path(a.data_dir), a.split)
    print(f"{a.dataset}/{a.split}: {path} (size and sha256 match the pin)")
    return 0


def cmd_evaluate_run(a: argparse.Namespace) -> int:
    import time

    from prompt_privacy.evaluation import datasets, scoring, systems

    ds = datasets.DATASETS[a.dataset]
    a.split = a.split or next(iter(ds.splits))
    path = datasets.verify(ds, Path(a.data_dir), a.split)
    if a.system == "presidio":
        if not a.model_path:
            print("refused: --system presidio needs --model-path (a local spaCy model directory)")
            return 2
        system = systems.presidio(Path(a.model_path), a.batch_size)
    else:
        system = systems.ppe_rules(phone_context=a.phone_context == "required")
    thresholds = sorted({float(x) for x in a.min_score.split(",")})
    scorers = {
        t: scoring.Scorer(
            ds.label_map, ds.compatible, system.claimed, ds.label_prefixes, ds.compatible_prefixes
        )
        for t in thresholds
    }
    t0 = time.perf_counter()
    batch: list[scoring.Doc] = []

    def flush() -> None:
        for doc, spans in zip(batch, system.run([d.text for d in batch]), strict=True):
            for t, sc in scorers.items():
                sc.add(doc, [s for s in spans if s.score >= t])
        batch.clear()

    for doc in datasets.load(ds, path, a.limit):
        batch.append(doc)
        if len(batch) >= a.batch_size:
            flush()
    flush()
    elapsed = time.perf_counter() - t0
    docs = scorers[thresholds[0]].docs
    print(
        f"{ds.name}/{a.split} ({docs} docs, {docs / elapsed:.0f} docs/s), {system.name} "
        + " ".join(f"{k}={v}" for k, v in system.config.items() if k not in ("recognizers", "entities"))
    )
    for t, sc in scorers.items():
        report = {
            "dataset": {
                "name": ds.name,
                "repo": ds.repo,
                "revision": ds.revision,
                "split": a.split,
                "file_sha256": ds.splits[a.split].sha256,
                "licence": ds.licence,
                "attribution": ds.attribution,
                "notes": list(ds.notes),
            },
            "system": {"name": system.name, **system.config, "min_score": t},
            "limit": a.limit,
            **sc.report(),
        }
        print(f"\nmin_score={t}\n")
        print(scoring.table(report))
        if a.json:
            out = Path(a.json)
            if len(thresholds) > 1:
                out = out.with_name(f"{out.stem}-min{t:g}{out.suffix}")
            out.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
            print(f"\nreport (labels and counts only) -> {out}")
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


def cmd_serve(a: argparse.Namespace) -> int:
    try:
        from prompt_privacy.proxy.app import RefusedConfig, Settings, check_listen, serve
        from prompt_privacy.proxy.observe import Observer
    except ImportError as e:
        print(f"ppe serve needs the 'serve' extra (pip install 'prompt-privacy-enhancement[serve]'): {e}")
        return 2
    from prompt_privacy.audit.keys import AuditPublicKey
    from prompt_privacy.audit.log import AuditLog

    host, _, port = a.listen.rpartition(":")
    settings = Settings(upstream=a.upstream, conversation_header=a.conversation_header)
    try:
        check_listen(host)
        settings.check()
    except RefusedConfig as e:
        print(f"refused: {e}")
        return 2
    d = Path(a.dir)
    audit = AuditLog(
        Path(a.log),
        AuditPublicKey((d / "machine.pub").read_bytes()),
        AuditPublicKey((d / "token.pub").read_bytes()),
        a.profile,
    )
    serve(settings, Observer(audit), host, int(port))
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

    from prompt_privacy.evaluation.datasets import DATASETS  # stdlib only; pyarrow loads on `run`

    ev = sub.add_parser(
        "evaluate", help="score detection on a pinned public dataset (labels and counts only)"
    ).add_subparsers(dest="ecmd", required=True)
    s = ev.add_parser("list", help="pinned datasets")
    s.set_defaults(fn=cmd_evaluate_list)
    for name, fn, helptext in (
        ("fetch", cmd_evaluate_fetch, "download a split; kept only if size and sha256 match the pin"),
        ("run", cmd_evaluate_run, "score a system (PPE rules, Presidio) on a fetched split"),
    ):
        s = ev.add_parser(name, help=helptext)
        s.add_argument("dataset", choices=tuple(DATASETS))
        s.add_argument(
            "--data-dir", required=True, help="outside the repository; datasets are never committed"
        )
        s.add_argument("--split", help="default: the dataset's first split (test; all for creddata)")
        s.set_defaults(fn=fn)
        if name == "run":
            s.add_argument("--system", choices=("ppe-rules", "presidio"), default="ppe-rules")
            s.add_argument("--limit", type=int, help="first N documents only")
            s.add_argument("--phone-context", choices=("optional", "required"), default="optional")
            s.add_argument("--model-path", help="presidio: local spaCy model directory (never a hub name)")
            s.add_argument("--batch-size", type=int, default=32)
            s.add_argument(
                "--min-score", default="0", help="comma-separated score thresholds, one report each"
            )
            s.add_argument("--json", help="write the full report (no dataset text) to this file")

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

    s = sub.add_parser(
        "serve", help="loopback proxy, shadow mode: forwards unchanged, records sealed findings"
    )
    s.add_argument("--listen", default="127.0.0.1:8787", help="loopback address:port only")
    s.add_argument("--upstream", default="https://api.anthropic.com")
    s.add_argument("--conversation-header", default="x-claude-code-session-id")
    s.add_argument(
        "--dir", default=".ppe-dev/audit", help="holds machine.pub and token.pub (ppe audit keygen)"
    )
    s.add_argument("--log", default=".ppe-dev/audit/audit.jsonl")
    s.add_argument("--profile", default="lab")
    s.set_defaults(fn=cmd_serve)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    rc: int = args.fn(args)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())

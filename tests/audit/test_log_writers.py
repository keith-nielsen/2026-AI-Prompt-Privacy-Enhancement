"""Audit log: shared writers and crash recovery (review F-11)."""

import hashlib
import threading
from pathlib import Path

from prompt_privacy.audit.keys import AuditKeyPair
from prompt_privacy.audit.log import AuditLog, open_log, verify_chain


def _keys() -> tuple[AuditKeyPair, AuditKeyPair]:
    return AuditKeyPair.generate(), AuditKeyPair.generate()


def test_concurrent_writers_keep_one_chain(tmp_path: Path) -> None:
    m, u = _keys()
    p = tmp_path / "a.jsonl"
    writers = [AuditLog(p, m.public, u.public, "lab") for _ in range(4)]

    def work(i: int) -> None:
        for n in range(25):
            writers[i].append({"event": "w", "i": i, "n": n})

    threads = [threading.Thread(target=work, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    v = verify_chain(p)
    assert v.ok and v.count == 100
    got = sorted((r["i"], r["n"]) for r in open_log(p, m, u))
    assert got == [(i, n) for i in range(4) for n in range(25)]


def test_torn_tail_longer_than_one_read_block_is_recovered(tmp_path: Path) -> None:
    m, u = _keys()
    p = tmp_path / "a.jsonl"
    log = AuditLog(p, m.public, u.public, "lab")
    log.append({"event": "first"})
    fragment = b'{"v":2,"seq":1,"ct":"' + b"A" * 200_000  # no newline: an append cut short
    with p.open("ab") as f:
        f.write(fragment)
    v = verify_chain(p)
    assert not v.ok and v.error.startswith("torn tail") and v.count == 1
    log.append({"event": "after-crash"})
    assert verify_chain(p).ok
    recs = list(open_log(p, m, u))
    assert [r["event"] for r in recs] == ["first", "recovered", "after-crash"]
    assert recs[1]["torn_bytes"] == len(fragment)
    assert recs[1]["torn_sha256"] == hashlib.sha256(fragment).hexdigest()


def test_file_that_is_only_a_torn_line_restarts_at_genesis(tmp_path: Path) -> None:
    m, u = _keys()
    p = tmp_path / "a.jsonl"
    p.write_bytes(b'{"v":2,"seq":0,"pr')
    assert verify_chain(p).error.startswith("torn tail")
    AuditLog(p, m.public, u.public, "lab").append({"event": "x"})
    assert verify_chain(p).ok
    assert [(r["seq"], r["event"]) for r in open_log(p, m, u)] == [(0, "recovered"), (1, "x")]


def test_unreadable_record_inside_the_log_is_reported(tmp_path: Path) -> None:
    m, u = _keys()
    p = tmp_path / "a.jsonl"
    log = AuditLog(p, m.public, u.public, "lab")
    for i in range(3):
        log.append({"i": i})
    lines = p.read_text().splitlines()
    lines[1] = lines[1][:40]
    p.write_text("\n".join(lines) + "\n")
    v = verify_chain(p)
    assert not v.ok and v.error == "unreadable record at line 2"

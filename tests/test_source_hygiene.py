"""Trojan Source guard (CVE-2021-42574): no invisible or bidi control characters in source files."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_BAD = re.compile(
    "["
    + "".join(chr(c) for c in (0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x2060, 0xFEFF, 0x00AD))
    + "".join(chr(c) for c in range(0x202A, 0x202F))
    + "".join(chr(c) for c in range(0x2066, 0x206A))
    + "]"
)


def test_no_invisible_or_bidi_characters() -> None:
    offenders = []
    for path in [
        *ROOT.glob("src/**/*.py"),
        *ROOT.glob("tests/**/*.py"),
        *ROOT.glob("schemas/*.json"),
        *ROOT.glob("policies/*.yaml"),
    ]:
        for n, line in enumerate(path.read_text().splitlines(), 1):
            if _BAD.search(line):
                offenders.append(f"{path.relative_to(ROOT)}:{n}")
    assert offenders == []

"""Synthetic labelled corpus (fixed seed) for detection benchmarks. No real personal data, ever.

Values are generated, never collected. Where a reserved range exists it is used (e-mail domains under
the RFC 6761 `.test`/`.example`/`.invalid` TLDs, RFC 5737/3849 IPs, NANP 555-01xx, UK Ofcom drama
numbers). Types without a reserved range (SG phones, NRIC/FIN, card numbers, IBANs) are random but
checksum-valid so the detectors are exercised; a generated value can coincide with a real one by
chance, so the corpus is generated at test time and not committed (`corpus-out/` is git-ignored).

Each item carries gold spans with an `expected_gap` flag for variants Stage 1 is known not to handle
(spelled-out digits, base64, identifiers split across sentences). The bench reports them separately.
"""

from __future__ import annotations

import base64
import json
import random
import string
from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass, field
from pathlib import Path

from prompt_privacy.core.checksums import iban_check_digits, luhn_check_digit, nric_check_letter

CORPUS_VERSION = 1

_GIVEN = (
    "Alicia",
    "Bao",
    "Chinedu",
    "Dewi",
    "Emre",
    "Fatimah",
    "Gareth",
    "Hui Min",
    "Ishaan",
    "Joanna",
    "Kavitha",
    "Luca",
    "Mohd Azlan",
    "Nadia",
    "Oliver",
    "Pei Shan",
    "Rashid",
    "Sunita",
    "Tobias",
    "Wen Jie",
)
_FAMILY = (
    "Abdullah",
    "Bergstrom",
    "Chua",
    "Dasgupta",
    "Ellison",
    "Fong",
    "Gunawardena",
    "Hendricks",
    "Iyer",
    "Jaafar",
    "Kowalski",
    "Lim",
    "Mendoza",
    "Ng",
    "Ortiz",
    "Perumal",
    "Rasmussen",
    "Seah",
    "Tay",
    "Wong",
)
_DOMAINS = (
    "acme-corp.test",
    "harbour-clinic.example",
    "lionbank.test",
    "mail.invalid",
    "orchard-law.example",
)
_SPELL = {
    "0": "zero",
    "1": "one",
    "2": "two",
    "3": "three",
    "4": "four",
    "5": "five",
    "6": "six",
    "7": "seven",
    "8": "eight",
    "9": "nine",
}


@dataclass
class Span:
    start: int
    end: int
    type: str
    variant: str = "plain"
    expected_gap: bool = False
    detector: str = "rules"  # rules | ner (needs a span model, Stage 2)


@dataclass
class Item:
    id: str
    locale: str
    template: str
    text: str
    spans: list[Span] = field(default_factory=list)


class _Builder:
    """Concatenates literal text and labelled values while tracking offsets."""

    def __init__(self) -> None:
        self.parts: list[str] = []
        self.spans: list[Span] = []
        self.pos = 0

    def lit(self, s: str) -> _Builder:
        self.parts.append(s)
        self.pos += len(s)
        return self

    def val(
        self, s: str, etype: str, variant: str = "plain", gap: bool = False, detector: str = "rules"
    ) -> _Builder:
        self.spans.append(Span(self.pos, self.pos + len(s), etype, variant, gap, detector))
        return self.lit(s)

    @property
    def text(self) -> str:
        return "".join(self.parts)


class Generator:
    def __init__(self, seed: int = 20261002) -> None:
        self.r = random.Random(seed)  # noqa: S311 — synthetic test data, not secrecy

    # --- value factories --------------------------------------------------------------------
    def nric(self) -> str:
        prefix = self.r.choice("STFGM")
        digits = "".join(self.r.choice(string.digits) for _ in range(7))
        return prefix + digits + nric_check_letter(prefix, digits)

    def card(self) -> str:
        kind = self.r.choice(("visa", "mc", "amex"))
        if kind == "amex":
            body = self.r.choice(("34", "37")) + "".join(self.r.choice(string.digits) for _ in range(12))
        else:
            first = "4" if kind == "visa" else f"5{self.r.randint(1, 5)}"
            body = first + "".join(self.r.choice(string.digits) for _ in range(15 - len(first)))
        return body + str(luhn_check_digit(body))

    def iban(self) -> str:
        country = self.r.choice(("GB", "DE", "NL", "FR"))
        if country == "GB":
            bban = "".join(self.r.choice(string.ascii_uppercase) for _ in range(4)) + "".join(
                self.r.choice(string.digits) for _ in range(14)
            )
        elif country == "NL":
            bban = "".join(self.r.choice(string.ascii_uppercase) for _ in range(4)) + "".join(
                self.r.choice(string.digits) for _ in range(10)
            )
        elif country == "DE":
            bban = "".join(self.r.choice(string.digits) for _ in range(18))
        else:
            bban = "".join(self.r.choice(string.digits) for _ in range(23))
        return country + iban_check_digits(country, bban) + bban

    def person(self) -> str:
        return f"{self.r.choice(_GIVEN)} {self.r.choice(_FAMILY)}"

    def email(self, name: str | None = None) -> str:
        n = (name or self.person()).lower().replace(" ", self.r.choice((".", "_", "")))
        return f"{n}{self.r.choice(('', str(self.r.randint(1, 99))))}@{self.r.choice(_DOMAINS)}"

    def phone(self, locale: str) -> str:
        if locale == "sg":
            n = self.r.choice("89") + "".join(self.r.choice(string.digits) for _ in range(7))
            return self.r.choice((f"+65 {n[:4]} {n[4:]}", f"{n[:4]} {n[4:]}", n, f"+65{n}"))
        if locale == "us":
            area = f"{self.r.randint(2, 9)}{self.r.randint(0, 9)}{self.r.randint(0, 9)}"
            line = f"01{self.r.randint(0, 99):02d}"
            return self.r.choice((f"({area}) 555-{line}", f"+1 {area} 555 {line}", f"{area}-555-{line}"))
        n = f"900{self.r.randint(0, 999):03d}"
        return self.r.choice((f"07700 {n}", f"+44 7700 {n}"))

    def ipv4(self) -> str:
        net = self.r.choice(("192.0.2", "198.51.100", "203.0.113", "10.20.30"))
        return f"{net}.{self.r.randint(1, 254)}"

    def ipv6(self) -> str:
        return f"2001:db8:{self.r.randint(1, 0xFFFF):x}::{self.r.randint(1, 0xFFFF):x}"

    def secret(self) -> tuple[str, str]:
        kind = self.r.choice(("aws", "github", "anthropic", "pem", "env"))
        b32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        alnum = string.ascii_letters + string.digits
        if kind == "aws":
            return "AKIA" + "".join(self.r.choice(b32) for _ in range(16)), kind
        if kind == "github":
            return "ghp_" + "".join(self.r.choice(alnum) for _ in range(36)), kind
        if kind == "anthropic":
            return "sk-ant-api03-" + "".join(self.r.choice(alnum + "-_") for _ in range(40)), kind
        if kind == "pem":
            body = base64.b64encode(bytes(self.r.randint(0, 255) for _ in range(48))).decode()
            return f"-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----", kind
        return "".join(self.r.choice(alnum) for _ in range(24)), kind

    # --- adversarial variants ---------------------------------------------------------------
    def variant(self, value: str, etype: str) -> tuple[str, str, bool]:
        """(rendered value, variant name, expected_gap)."""
        roll = self.r.random()
        if roll < 0.70:
            return self._format(value, etype), "plain", False
        if roll < 0.78:
            i = self.r.randint(1, max(1, len(value) - 1))
            return value[:i] + "\u200b" + value[i:], "zero_width", False
        if roll < 0.85:
            return (
                value.translate({ord(c): ord(c) + 0xFEE0 for c in string.ascii_letters + string.digits}),
                "fullwidth",
                False,
            )
        if roll < 0.90 and etype in ("NRIC", "EMAIL", "IBAN"):
            return value.lower(), "lowercase", False
        if roll < 0.95 and etype in ("NRIC", "CARD", "PHONE"):
            return " ".join(_SPELL.get(c, c) for c in value), "spelled_digits", True
        return base64.b64encode(value.encode()).decode(), "base64", True

    def _format(self, value: str, etype: str) -> str:
        if etype == "CARD" and self.r.random() < 0.6:
            sep = self.r.choice((" ", "-"))
            return sep.join(value[i : i + 4] for i in range(0, len(value), 4))
        if etype == "IBAN" and self.r.random() < 0.6:
            return " ".join(value[i : i + 4] for i in range(0, len(value), 4))
        return value

    # --- templates ----------------------------------------------------------------------------
    def _chat(self, b: _Builder, loc: str) -> None:
        name = self.person()
        b.lit(self.r.choice(("Hi, my name is ", "This is ", "Customer: "))).val(
            name, "PERSON", detector="ner"
        )
        v, var, gap = self.variant(self.nric(), "NRIC")
        b.lit(" and my NRIC is ").val(v, "NRIC", var, gap)
        b.lit(". You can reach me at ").val(self.phone(loc), "PHONE")
        v, var, gap = self.variant(self.email(name), "EMAIL")
        b.lit(" or ").val(v, "EMAIL", var, gap).lit(".")

    def _payment(self, b: _Builder, loc: str) -> None:
        v, var, gap = self.variant(self.card(), "CARD")
        b.lit("Please refund the charge on card ").val(v, "CARD", var, gap)
        v, var, gap = self.variant(self.iban(), "IBAN")
        b.lit(" to account ").val(v, "IBAN", var, gap)
        day = f"2026-0{self.r.randint(1, 9)}-1{self.r.randint(0, 9)}"
        b.lit(f". Invoice INV-{self.r.randint(10000, 99999)} dated {day}.")

    def _env_file(self, b: _Builder, loc: str) -> None:
        aws, _ = self.secret()
        while not aws.startswith("AKIA"):
            aws, _ = self.secret()
        b.lit("# service config\nAWS_ACCESS_KEY_ID=").val(aws, "SECRET", "aws")
        pw = "".join(self.r.choice(string.ascii_letters + string.digits) for _ in range(20))
        b.lit("\nDB_PASSWORD=").val(pw, "SECRET", "env").lit("\nDB_HOST=").val(self.ipv4(), "IPV4")
        b.lit(f"\nLOG_LEVEL=info\nBUILD={self.r.randint(100, 999)}\n")

    def _tool_json(self, b: _Builder, loc: str) -> None:
        name = self.person()
        b.lit('{"tool":"crm.lookup","result":{"name":"').val(name, "PERSON", detector="ner")
        b.lit('","email":"').val(self.email(name), "EMAIL")
        b.lit('","phone":"').val(self.phone(loc), "PHONE")
        v6 = self.r.random() < 0.3
        b.lit('","last_ip":"').val(self.ipv6() if v6 else self.ipv4(), "IPV6" if v6 else "IPV4")
        b.lit('","order":"').lit(f"{self.r.randint(1000, 9999)}-{self.r.randint(1000, 9999)}").lit('"}}')

    def _secret_prose(self, b: _Builder, loc: str) -> None:
        s, kind = self.secret()
        while kind == "env":
            s, kind = self.secret()
        b.lit("Debugging the deploy, this is the key I'm using:\n").val(s, "SECRET", kind)
        b.lit(f"\nCommit {''.join(self.r.choice('0123456789abcdef') for _ in range(40))} broke it.")

    def _split(self, b: _Builder, loc: str) -> None:
        n = self.nric()
        b.lit("First part of my ID is ").val(n[:4], "NRIC", "split", True)
        b.lit(", and the rest is ").val(n[4:], "NRIC", "split", True).lit(".")

    def _csv(self, b: _Builder, loc: str) -> None:
        # A table: the column header is the only context for the phone numbers, several rows above.
        b.lit("customer_id,name,phone,email\n")
        for _ in range(self.r.randint(2, 4)):
            name = self.person()
            b.lit(f"{self.r.randint(10000, 99999)},").val(name, "PERSON", detector="ner").lit(",")
            b.val(self.phone(loc), "PHONE").lit(",").val(self.email(name), "EMAIL").lit("\n")

    def _negative(self, b: _Builder, loc: str) -> None:
        bad = self.nric()
        bad = bad[:-1] + ("A" if bad[-1] != "A" else "B")
        not_luhn = self.card()
        not_luhn = not_luhn[:-1] + str((int(not_luhn[-1]) + 1) % 10)
        when = f"2026-10-0{self.r.randint(1, 9)} 14:3{self.r.randint(0, 9)}"
        b.lit(f"Ticket {self.r.randint(100000, 999999)} opened {when}. ")
        b.lit(f"Reference {bad} is not a valid ID; card-like number {not_luhn} fails checks. ")
        isbn = f"978-0-{self.r.randint(100, 999)}-{self.r.randint(10000, 99999)}-{self.r.randint(0, 9)}"
        price = f"{self.r.randint(10, 999)}.{self.r.randint(10, 99)}"
        b.lit(f"Version 1.{self.r.randint(0, 20)}.{self.r.randint(0, 99)}, ISBN {isbn}, price SGD {price}, ")
        b.lit(f"uuid 3f2c{self.r.randint(1000, 9999)}-aa1b-4c2d-9e8f-0123456789ab, address 999.1.2.3.")

    TEMPLATES: dict[str, Callable[[Generator, _Builder, str], None]] = {
        "chat": _chat,
        "payment": _payment,
        "env_file": _env_file,
        "tool_json": _tool_json,
        "secret_prose": _secret_prose,
        "split": _split,
        "negative": _negative,
        "csv": _csv,
    }

    def items(self, n: int) -> Iterator[Item]:
        names = list(self.TEMPLATES)
        weights = [5, 4, 2, 3, 3, 1, 3, 2]
        for i in range(n):
            loc = self.r.choice(("sg", "sg", "us", "uk"))
            tname = self.r.choices(names, weights)[0]
            b = _Builder()
            self.TEMPLATES[tname](self, b, loc)
            yield Item(f"c{CORPUS_VERSION}-{i:06d}", loc, tname, b.text, b.spans)


def write_jsonl(path: Path, n: int, seed: int) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w") as f:
        for item in Generator(seed).items(n):
            f.write(json.dumps(asdict(item), ensure_ascii=False) + "\n")
            count += 1
    return count

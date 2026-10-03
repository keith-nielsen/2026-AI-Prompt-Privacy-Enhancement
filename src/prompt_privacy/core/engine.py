"""Mask a conversation for the cloud leg and restore replies (ADR-0002 R1–R6, ADR-0008).

Conversation order is the issue order, so surrogates are stable across turns. Non-assistant messages
get fresh detection; assistant (provider-authored) messages get the inverse map only, so a history the
client resends masks back to exactly what the provider produced (R3).
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field

from prompt_privacy.core.keys import TokenKey
from prompt_privacy.core.normalise import norm
from prompt_privacy.core.surrogates import Guarantee, Surrogator, transfer_format
from prompt_privacy.core.types import EntityType, Finding
from prompt_privacy.core.vault import Entry, Vault
from prompt_privacy.detectors.base import Dictionary, detect

_FORMAT_TYPES = {EntityType.NRIC, EntityType.CARD, EntityType.IBAN, EntityType.PHONE}
_TOKEN = re.compile(r"(\\?<)?\b([A-Za-z]+)_([a-z2-7]{16}|[a-z2-7]{10})\b(\\?>)?", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class Message:
    role: str  # system | user | assistant | tool
    text: str


@dataclass
class MaskResult:
    messages: list[Message]
    vault: Vault
    findings: list[tuple[int, Finding]] = field(default_factory=list)  # (message index, finding)


@dataclass
class RestoreResult:
    text: str
    restored: int = 0
    misses: int = 0  # token-shaped strings not in the vault (left as-is)


def _splice(text: str, edits: Sequence[tuple[int, int, str]]) -> str:
    out = text
    for s, e, rep in sorted(edits, key=lambda x: -x[0]):
        out = out[:s] + rep + out[e:]
    return out


class Engine:
    def __init__(self, key: TokenKey, dictionary: Dictionary | None = None, form: str = "surrogate") -> None:
        self.surrogator = Surrogator(key)
        self.key = key
        self.dictionary = dictionary
        self.form = form

    # --- masking -------------------------------------------------------------------------------
    def mask(self, messages: Sequence[Message], conversation_key: str) -> MaskResult:
        all_text = "\n".join(m.text for m in messages)
        vault = Vault(self.surrogator, self.key.scope(conversation_key), all_text, self.form)
        per_msg: list[list[Finding]] = []
        for m in messages:
            fs = [] if m.role == "assistant" else detect(m.text, self.dictionary)
            per_msg.append(fs)
            for f in fs:
                vault.note_original(f.type, f.value)
        result = MaskResult([], vault)
        for i, (m, fs) in enumerate(zip(messages, per_msg, strict=True)):
            if m.role == "assistant":
                result.messages.append(Message(m.role, self.inverse_map(m.text, vault)))
                continue
            edits = []
            for f in fs:
                entry = vault.issue(f.type, f.value)
                edits.append((f.start, f.end, entry.surrogate.render(f.value)))
                result.findings.append((i, f))
            result.messages.append(Message(m.role, _splice(m.text, edits)))
        return result

    def inverse_map(self, text: str, vault: Vault) -> str:
        """Real values (restored earlier) → their surrogates, preserving the format used (R3)."""
        edits: list[tuple[int, int, str]] = []
        taken: list[tuple[int, int]] = []

        def free(s: int, e: int) -> bool:
            return all(e <= a or s >= b for a, b in taken)

        for f in detect(text, self.dictionary):
            entry = vault.entries.get((f.type, norm(f.type, f.value)))
            if entry is not None and free(f.start, f.end):
                edits.append((f.start, f.end, entry.surrogate.render(f.value)))
                taken.append((f.start, f.end))
        for entry in sorted(vault.entries.values(), key=lambda e: -max(len(s) for s in e.surfaces)):
            for surface in entry.surfaces:
                for m in re.finditer(re.escape(surface), text):
                    if free(m.start(), m.end()):
                        edits.append((m.start(), m.end(), entry.surrogate.render(surface)))
                        taken.append((m.start(), m.end()))
        for entry in vault.entries.values():
            for original, sur in entry.surrogate.components:
                for m in re.finditer(rf"(?<!\w){re.escape(original)}(?!\w)", text):
                    if free(m.start(), m.end()):
                        edits.append((m.start(), m.end(), sur))
                        taken.append((m.start(), m.end()))
        return _splice(text, edits)

    @staticmethod
    def _real_in_format(entry: Entry, occurrence: str) -> str:
        """The real value written in the format the model used for its surrogate (keeps R3 exact)."""
        if entry.etype in _FORMAT_TYPES:
            return transfer_format(occurrence, entry.value_norm) or entry.surfaces[0]
        return entry.surfaces[0]

    # --- restoring -----------------------------------------------------------------------------
    def restore(self, text: str, vault: Vault) -> RestoreResult:
        res = RestoreResult(text)
        edits: list[tuple[int, int, str]] = []
        taken: list[tuple[int, int]] = []

        def free(s: int, e: int) -> bool:
            return all(e <= a or s >= b for a, b in taken)

        def put(s: int, e: int, rep: str) -> None:
            edits.append((s, e, rep))
            taken.append((s, e))
            res.restored += 1

        entries = list(vault.entries.values())
        # 1. exact canonical surrogates and tokens (longest first)
        for entry in sorted(entries, key=lambda x: -len(x.surrogate.canonical)):
            for m in re.finditer(re.escape(entry.surrogate.canonical), text):
                if free(m.start(), m.end()):
                    put(m.start(), m.end(), self._real_in_format(entry, m.group()))
        # 2. reformatted structured surrogates: shape-only detection, compare normalised (closed world)
        for f in detect(text, strict=False):
            if f.type not in _FORMAT_TYPES or not free(f.start, f.end):
                continue
            hit = vault.by_surrogate_norm(f.type, f.value)
            if hit is not None and hit.surrogate.guarantee is not Guarantee.TOKEN:
                put(f.start, f.end, self._real_in_format(hit, f.value))
        # 3. tolerant typed tokens: exact suffix, case/brackets/escaping may vary (R2)
        tokens = {
            e.surrogate.canonical[1:-1].split("_", 1)[1]: e
            for e in entries
            if e.surrogate.guarantee is Guarantee.TOKEN
        }
        for m in _TOKEN.finditer(text):
            if not free(m.start(), m.end()):
                continue
            tok = tokens.get(m.group(3).lower())  # base32: case carries no information
            if tok is not None and m.group(2).upper() == tok.etype.value:
                put(m.start(), m.end(), tok.surfaces[0])
            else:
                res.misses += 1
        # 4. person name components ("Ms Koh" → "Ms Tan"), whole words in name case only
        for entry in entries:
            for original, sur in entry.surrogate.components:
                for m in re.finditer(rf"(?<!\w){re.escape(sur)}(?!\w)", text):
                    if free(m.start(), m.end()):
                        put(m.start(), m.end(), original)
        res.text = _splice(text, edits)
        return res

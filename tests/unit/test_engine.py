import re

from hypothesis import given, settings
from hypothesis import strategies as st

from prompt_privacy.core.engine import Engine, Message
from prompt_privacy.core.keys import TokenKey
from prompt_privacy.core.types import EntityType as T

USER = (
    "I'm Jane Tan, NRIC S1234567D, card 4111 1111 1111 1111, mail jane.tan@acme-corp.test, +1 415 555 2671."
)


def entry(res, etype):  # type: ignore[no-untyped-def]
    return next(e for (t, _), e in res.vault.entries.items() if t is etype)


def test_masked_text_contains_no_real_values(engine: Engine) -> None:
    res = engine.mask([Message("user", USER)], "c1")
    out = res.messages[0].text
    for real in ("Jane Tan", "S1234567D", "4111 1111 1111 1111", "jane.tan@acme-corp.test", "415 555 2671"):
        assert real not in out


def test_stable_across_turns(engine: Engine) -> None:
    a = engine.mask([Message("user", USER)], "c1").messages[0].text
    b = (
        engine.mask([Message("user", USER), Message("assistant", "ok"), Message("user", "thanks")], "c1")
        .messages[0]
        .text
    )
    assert a == b


def test_restore_reformatted_and_partial_names(engine: Engine) -> None:
    res = engine.mask([Message("user", USER)], "c1")
    nric, phone, person = entry(res, T.NRIC), entry(res, T.PHONE), entry(res, T.PERSON)
    family = person.surrogate.components[-1][1]
    reply = f"Ms {family}, ID {nric.surrogate.canonical.lower()}, phone {phone.surrogate.canonical}."
    out = engine.restore(reply, res.vault)
    assert out.text == "Ms Tan, ID s1234567d, phone +14155552671."


def test_tokens_tolerate_case_and_brackets(key: TokenKey) -> None:
    eng = Engine(key, form="token")
    res = eng.mask([Message("user", "card 4111 1111 1111 1111")], "c")
    tok = entry(res, T.CARD).surrogate.canonical  # <CARD_xxxxxxxxxx>
    mangled = f"see {tok[1:-1].upper()} and \\{tok[:-1]}\\>"
    out = eng.restore(mangled, res.vault)
    assert out.text.count("4111 1111 1111 1111") == 2 and out.misses == 0


def test_tool_arguments_are_json_safe(engine: Engine) -> None:
    res = engine.mask([Message("user", 'send to "jane.tan@acme-corp.test"')], "c")
    sur = entry(res, T.EMAIL).surrogate.canonical
    out = engine.restore('{"to": "' + sur + '"}', res.vault)
    assert out.text == '{"to": "jane.tan@acme-corp.test"}'


_FORMATS = st.sampled_from(["{}", "{} ", " ({})", "**{}**"])


@settings(max_examples=60, deadline=None)
@given(order=st.permutations(range(4)), fmt=_FORMATS, reformat=st.booleans())
def test_r3_round_trip_property(order: list[int], fmt: str, reformat: bool) -> None:
    """For provider output x built from surrogates (optionally reformatted), mask(restore(x)) == x."""
    eng = Engine(TokenKey(bytes(32)))
    res = eng.mask([Message("user", USER)], "prop")
    surs = [e.surrogate.canonical for e in res.vault.entries.values() if e.etype is not T.PERSON]
    if reformat:
        surs = [re.sub(r"[ -]", "", s) for s in surs]
    x = "Reply: " + " / ".join(fmt.format(surs[i % len(surs)]) for i in order)
    restored = eng.restore(x, res.vault).text
    assert restored != x
    again = eng.mask([Message("user", USER), Message("assistant", restored)], "prop")
    assert again.messages[1].text == x

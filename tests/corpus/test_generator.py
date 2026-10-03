from prompt_privacy.corpus.generator import Generator


def test_deterministic() -> None:
    assert [i.text for i in Generator(5).items(100)] == [i.text for i in Generator(5).items(100)]


def test_spans_are_consistent_and_synthetic() -> None:
    for item in Generator(9).items(500):
        for s in item.spans:
            assert 0 <= s.start < s.end <= len(item.text)
        for s in item.spans:
            if s.type == "EMAIL" and s.variant == "plain":
                assert (
                    item.text[s.start : s.end].rsplit("@", 1)[1].endswith((".test", ".example", ".invalid"))
                )

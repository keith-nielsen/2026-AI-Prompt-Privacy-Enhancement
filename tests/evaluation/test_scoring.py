"""The scoring protocol on hand-built documents: each view counts what its docstring says it counts."""

import json

from prompt_privacy.evaluation.scoring import Doc, Scorer, Span, table

MAP = {"email": "EMAIL", "phone_number": "PHONE", "fax_number": "PHONE"}
COMPAT = {"IBAN": frozenset({"account_number"})}


def score(docs: list[tuple[Doc, list[Span]]]) -> dict:  # type: ignore[type-arg]
    s = Scorer(MAP, COMPAT)
    for d, p in docs:
        s.add(d, p)
    return s.report()


def doc(gold: list[Span], tags: tuple[tuple[str, str], ...] = ()) -> Doc:
    return Doc("u", "x" * 100, tuple(gold), tags)


def test_strict_and_overlap_differ_on_boundaries() -> None:
    d = doc([Span(0, 10, "email"), Span(20, 30, "email")])
    r = score([(d, [Span(0, 10, "EMAIL"), Span(22, 28, "EMAIL")])])["by_type"]["EMAIL"]
    assert (r["support"], r["found_overlap"], r["found_strict"]) == (2, 2, 1)
    assert (r["recall_overlap"], r["recall_strict"], r["precision_typed"]) == (1.0, 0.5, 1.0)


def test_wrong_type_covers_but_is_not_found() -> None:
    d = doc([Span(0, 10, "email")])
    r = score([(d, [Span(0, 10, "PHONE")])])
    assert r["by_type"]["EMAIL"]["found_overlap"] == 0
    assert r["by_label"]["email"]["covered_any_type"] == 1
    assert r["by_type"]["PHONE"]["precision_typed"] == 0.0
    assert r["by_type"]["PHONE"]["precision_any_label"] == 1.0
    assert r["confusion"]["PHONE"] == {"email": 1}


def test_many_labels_to_one_type() -> None:
    d = doc([Span(0, 10, "phone_number"), Span(20, 30, "fax_number")])
    r = score([(d, [Span(0, 10, "PHONE")])])["by_type"]["PHONE"]
    assert (r["support"], r["found_overlap"], r["recall_overlap"]) == (2, 1, 0.5)


def test_unmapped_labels_count_for_coverage_only() -> None:
    d = doc([Span(0, 9, "ssn"), Span(20, 30, "email")])
    r = score([(d, [])])
    assert r["by_label"]["ssn"] == {
        "support": 1,
        "maps_to": None,
        "covered_any_type": 0,
        "coverage_any_type": 0.0,
    }
    assert r["by_type"]["EMAIL"]["support"] == 1 and "ssn" not in r["by_type"]
    assert r["any_type_coverage_all_labels"] == {"gold_spans": 2, "covered": 0, "rate": 0.0}


def test_compatible_label_is_precision_only() -> None:
    d = doc([Span(0, 22, "account_number")])
    r = score([(d, [Span(0, 22, "IBAN")])])["by_type"]["IBAN"]
    assert (r["support"], r["recall_overlap"], r["precision_typed"]) == (0, None, 1.0)


def test_false_positive_and_empty_system() -> None:
    d = doc([Span(0, 10, "email")])
    fp = score([(d, [Span(0, 10, "EMAIL"), Span(50, 60, "EMAIL")])])
    assert fp["by_type"]["EMAIL"]["precision_typed"] == 0.5
    assert fp["confusion"]["EMAIL"] == {"email": 1, "(no gold span)": 1}
    empty = score([(d, [])])["by_type"]["EMAIL"]
    assert (empty["recall_overlap"], empty["predicted"], empty["precision_typed"], empty["f1_overlap"]) == (
        0.0,
        0,
        None,
        None,
    )


def test_adjacent_spans_do_not_overlap() -> None:
    d = doc([Span(0, 10, "email")])
    r = score([(d, [Span(10, 20, "EMAIL")])])["by_type"]["EMAIL"]
    assert (r["found_overlap"], r["precision_any_label"]) == (0, 0.0)


def test_micro_and_slices() -> None:
    us = doc([Span(0, 10, "email"), Span(20, 30, "phone_number")], (("locale", "us"),))
    intl = doc([Span(0, 10, "phone_number")], (("locale", "intl"),))
    r = score([(us, [Span(0, 10, "EMAIL"), Span(20, 30, "PHONE")]), (intl, [])])
    assert r["micro_mapped_types"]["support"] == 3 and r["micro_mapped_types"]["found_overlap"] == 2
    assert r["by_slice"]["locale=us"]["PHONE"]["recall_overlap"] == 1.0
    assert r["by_slice"]["locale=intl"]["PHONE"]["recall_overlap"] == 0.0
    assert r["docs"] == 2


def test_report_and_table_hold_no_text() -> None:
    text = "contact zq7.unique-marker@example.test or +65 9123 4567 today"
    s, e = text.index("zq7"), text.index(" or")
    d = Doc("uid-secret-1", text, (Span(s, e, "email"),), (("locale", "us"),))
    sc = Scorer(MAP)
    sc.add(d, [Span(s, e, "EMAIL")])
    rendered = json.dumps(sc.report()) + table(sc.report())
    for fragment in ("zq7", "unique-marker", "9123", "uid-secret-1", "contact"):
        assert fragment not in rendered

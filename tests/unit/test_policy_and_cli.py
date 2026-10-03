from pathlib import Path

import jsonschema
import pytest

from prompt_privacy import knobs, policy
from prompt_privacy.cli.main import main
from prompt_privacy.selftest import run_all

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("name", ["lab", "personal", "team"])
def test_shipped_profiles_validate(name: str) -> None:
    policy.load(ROOT / "policies" / f"{name}.yaml")


def test_lab_only_values_rejected_elsewhere() -> None:
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({"profile": "team", "on_error": "pass_and_log"}, policy.schema("policy"))


def test_explain_names_every_knob_and_flags_unbuilt() -> None:
    text = knobs.explain(policy.load(ROOT / "policies" / "lab.yaml"))
    for k in knobs.KNOBS:
        assert k.path in text
    assert "[designed, not built yet]" in text


def test_scan_never_prints_values(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    f = tmp_path / "in.txt"
    f.write_text("NRIC S1234567D card 4111 1111 1111 1111")
    assert main(["scan", str(f)]) == 1
    out = capsys.readouterr().out
    assert "S1234567D" not in out and "4111 1111" not in out and "NRIC" in out


def test_selftests_pass() -> None:
    failed = [(n, d) for n, ok, d in run_all(n=150) if not ok]
    assert failed == []

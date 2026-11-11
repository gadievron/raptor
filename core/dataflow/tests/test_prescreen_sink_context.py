"""Charset exclusion is a model fact, not sink-interpretation authority."""
from types import SimpleNamespace

import pytest

from core.dataflow import injection_prescreen as ip
from core.dataflow.smt_barrier import ValidatorSpec
from core.smt_solver import z3_available

pytestmark = pytest.mark.skipif(not z3_available(), reason="z3-solver not installed")


@pytest.mark.parametrize("rule", ["py/path-injection", "py/command-injection",
                                  "py/sql-injection", "py/xss"])
def test_charset_model_does_not_refute_uninterpreted_sole_argument(tmp_path, rule):
    # The file is analysed as text only; consume is never imported or executed.
    (tmp_path / "app.py").write_text(
        "import re\ndef handle(value):\n"
        "    if not re.fullmatch(r'[A-Za-z0-9]+', value):\n"
        "        return\n"
        "    return consume(value)\n")
    def step(line):
        return SimpleNamespace(file_path="app.py", line=line)
    path = SimpleNamespace(source=step(2), sink=step(5), intermediate_steps=[step(3)])
    verdict = ip.prescreen_finding(paths=[path], repo_root=tmp_path, rule_id=rule)
    assert verdict is not None
    assert verdict.refuted is False
    assert verdict.paths_checked == 1
    assert verdict.evidence, "retain the successful narrow model observation"
    assert "sink" in verdict.reason and "context" in verdict.reason


def test_narrow_charset_exclusion_model_remains_available():
    spec = ValidatorSpec(kind="charset", var_name="value", charset="A-Za-z0-9")
    sound, reason, _ = ip._spec_neutralizes_all(spec, frozenset({"cmdi", "sqli"}))
    assert sound is True
    assert reason

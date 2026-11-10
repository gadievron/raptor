"""Live slice observations remain separate from source-refuting evidence."""
from dataclasses import asdict
import json
from pathlib import Path

import pytest

from core.dataflow import injection_prescreen as ip
from core.dataflow.tests.test_injection_prescreen import _path
from core.smt_solver import z3_available

pytestmark = pytest.mark.skipif(not z3_available(), reason="z3-solver not installed")


@pytest.fixture(autouse=True)
def owned_prescreen_stats(monkeypatch):
    monkeypatch.setattr(ip, "_STATS", ip.PrescreenStats())


def _source(operation):
    return (
        "import re\ndef handle(name):\n"
        "    if len(name) > 8: return\n"
        '    if not re.match(r"^[a-z]+$", name):\n'
        "        return\n"
        f"    trimmed = name{operation}\n"
        "    return os.system(trimmed)\n"
    )


@pytest.mark.parametrize("operation,expected", [("[:-1]", "excluded"), ("[1:]", "counterexample")],
                         ids=["drop-last", "drop-first"])
def test_live_prescreen_retains_conditional_models_without_refuting(tmp_path: Path, operation, expected):
    (tmp_path / "app.py").write_text(_source(operation))
    verdict = ip.prescreen_finding(
        paths=[_path("app.py", 2, [4], 7)], repo_root=tmp_path,
        rule_id="py/command-injection",
    )
    assert verdict is not None and verdict.refuted is False
    assert verdict.evidence == []
    assert verdict.paths_checked == 1
    diagnostic, = verdict.diagnostics
    assert diagnostic["status"] == expected
    assert diagnostic["source_bound"] is False
    assert diagnostic["path_index"] == 0
    assert diagnostic["sink_class"] == "cmdi"
    assert diagnostic["validator_file"] == "app.py"
    assert json.loads(json.dumps(asdict(verdict)))["diagnostics"][0]["status"] == expected
    assert ip.snapshot_stats() == {"attempted": 1, "lifted": 0, "refuted": 0, "no_signal": 1}
    if expected == "counterexample":
        assert diagnostic["output_value"] == diagnostic["input_value"][1:]
        assert "\n" in diagnostic["output_value"]


def test_conditional_models_cannot_cover_an_unchecked_alternative(tmp_path: Path):
    (tmp_path / "app.py").write_text(_source("[:-1]"))
    verdict = ip.prescreen_finding(
        paths=[_path("app.py", 2, [4], 7), _path("app.py", 2, [], 7)],
        repo_root=tmp_path, rule_id="py/command-injection",
    )
    assert verdict is not None and verdict.refuted is False
    assert verdict.paths_checked == 1
    assert all(model["path_index"] == 0 for model in verdict.diagnostics)
    assert verdict.evidence == []


def test_expired_aggregate_diagnostic_budget_retains_unknown(tmp_path: Path):
    from core.smt_solver.session import query_budget

    (tmp_path / "app.py").write_text(_source("[:-1]"))
    with query_budget(0):
        verdict = ip.prescreen_finding(
            paths=[_path("app.py", 2, [4], 7)], repo_root=tmp_path,
            rule_id="py/command-injection",
        )
    assert verdict is not None and verdict.refuted is False
    diagnostic, = verdict.diagnostics
    assert diagnostic["status"] == "unknown"
    assert diagnostic["input_value"] is diagnostic["output_value"] is None

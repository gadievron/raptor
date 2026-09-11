"""The refine-loop E2E harness must aggregate expectations into its exit code.

Pre-fix the harness printed 'should be ...' expectations without
comparing them and returned 0 unconditionally — a regression in
_refine_exploit_loop passed the designated wiring proof silently.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

_SCRIPT = (
    Path(__file__).resolve().parents[1] / "scripts" / "e2e_refine_exploit.py"
)


def _load():
    spec = importlib.util.spec_from_file_location("e2e_refine", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _stub_scenarios(mod, failures_by_scenario: list[list[str]]) -> None:
    names = [
        "scenario_1_converges_on_iteration_1",
        "scenario_2_exhausts_max_refinement",
        "scenario_3_llm_no_extractable_code",
        "scenario_4_no_multi_turn",
    ]
    for name, fails in zip(names, failures_by_scenario):
        setattr(mod, name, lambda work_dir, _f=fails: list(_f))


def test_check_records_failures():
    mod = _load()
    failures: list[str] = []
    mod._check(failures, "met", True)
    mod._check(failures, "not met", False)
    assert failures == ["not met"]


def test_main_exit_1_when_any_expectation_fails(capsys):
    mod = _load()
    _stub_scenarios(mod, [[], ["s2 refinement count == 3"], [], []])
    assert mod.main() == 1
    assert "E2E FAILED" in capsys.readouterr().out


def test_main_exit_0_when_all_expectations_met(capsys):
    mod = _load()
    _stub_scenarios(mod, [[], [], [], []])
    assert mod.main() == 0
    assert "E2E PASSED" in capsys.readouterr().out

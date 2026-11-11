"""The dataflow validator's injection-prescreen hook.

A charset model has no sink-interpretation authority and must continue
normal validation. No signal or a prescreen crash likewise leaves normal
validation available. Fixture source is analysed as text, never executed.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("z3")

from core.smt_solver.path_feasibility import PathSMTResult
from packages.codeql.tests.test_dataflow_validator import _validator, _FULL_RESPONSE
from packages.codeql.dataflow_validator import (
    DataflowPath,
    DataflowStep,
    DataflowValidator,
)

# The refuting charset is DOTLESS: '.' is a pathtrav danger char ('.'
# builds '..' segments), so dot-admitting charsets must decline.
# Keep the checked value in a direct alias; calls need their own transfer contract.
GUARD_APP = """\
import os
import re


def handler(request):
    name = request.args.get('name')
    if not re.match(r'^[A-Za-z0-9_+-]+$', name):
        return None
    cfg = name
    open(cfg)
"""


def _step(line: int, label: str) -> DataflowStep:
    return DataflowStep(file_path="app.py", line=line, column=1,
                        snippet="", label=label)


def _dataflow(rule_id: str = "py/path-injection") -> DataflowPath:
    return DataflowPath(
        source=_step(6, "source"),
        sink=_step(10, "sink"),
        intermediate_steps=[_step(7, "step")],
        sanitizers=[],
        rule_id=rule_id,
        message="user input flows to open()",
    )


@pytest.fixture
def guard_repo(tmp_path):
    (tmp_path / "app.py").write_text(GUARD_APP, encoding="utf-8")
    return tmp_path


def _exploding_llm() -> MagicMock:
    llm = MagicMock()
    llm.generate_structured.side_effect = AssertionError(
        "LLM must not be called when the prescreen refutes"
    )
    return llm


class TestPrescreenHook:
    def test_charset_model_continues_normal_validation(self, guard_repo, monkeypatch):
        validator = _validator()
        monkeypatch.setattr("core.llm.scorecard.prefilter_decision",
                            lambda *a, **k: SimpleNamespace(short_circuit=False))
        monkeypatch.setattr("core.llm.scorecard.record_prefilter_outcome", lambda *a, **k: None)
        with patch(
            "packages.codeql.dataflow_validator.check_path_feasibility_dual",
            return_value=PathSMTResult(
                feasible=False, reasoning="independent path result", satisfied=[],
                unknown=[], unsatisfied=[], smt_available=True, model={},
            ),
        ):
            result = validator.validate_dataflow_path(_dataflow(), guard_repo)
        validator._extract_path_conditions.assert_called_once()
        assert result.error is None
        assert result.is_exploitable is _FULL_RESPONSE["is_exploitable"]
        assert result.reasoning == _FULL_RESPONSE["reasoning"]
        assert result.smt_diagnostics["modeled_feasible"] is False
        assert not any("charset validator" in barrier for barrier in result.barriers)
        validator.llm.generate_structured.assert_called_once()

    def test_uncertified_call_result_does_not_refute(self, guard_repo):
        source = GUARD_APP.replace("    cfg = name\n",
                                   "    cfg = os.path.join('/etc/app', name)\n")
        (guard_repo / "app.py").write_text(source, encoding="utf-8")
        llm = _exploding_llm()
        result = DataflowValidator(llm)._injection_prescreen(_dataflow(), guard_repo)
        assert result is None
        llm.generate_structured.assert_not_called()

    def test_refutation_requires_every_alternative(self, guard_repo):
        # An alternative path with no liftable validator kills the
        # signal; the flow proceeds into the normal machinery (stubbed
        # here at the condition-extraction seam).
        dp = _dataflow()
        alt = _dataflow()
        alt.intermediate_steps = []
        dp.alternatives = [alt]
        llm = MagicMock()
        v = DataflowValidator(llm)
        with patch.object(
            v, "_extract_path_conditions", return_value=([], {}),
        ) as extract, patch(
            "packages.codeql.dataflow_validator.check_path_feasibility_dual",
            return_value=PathSMTResult(
                feasible=False, reasoning="stub", satisfied=[], unknown=[], unsatisfied=[],
                smt_available=True, model={},
            ),
        ):
            result = v.validate_dataflow_path(dp, guard_repo)
        assert extract.called  # prescreen declined; SMT loop ran
        assert "String-theory prescreen" not in result.reasoning

    def test_non_injection_rule_skips_prescreen(self, guard_repo):
        dp = _dataflow(rule_id="cpp/integer-overflow")
        llm = MagicMock()
        v = DataflowValidator(llm)
        with patch.object(
            v, "_extract_path_conditions", return_value=([], {}),
        ), patch(
            "packages.codeql.dataflow_validator.check_path_feasibility_dual",
            return_value=PathSMTResult(
                feasible=False, reasoning="stub", satisfied=[], unknown=[], unsatisfied=[],
                smt_available=True, model={},
            ),
        ):
            result = v.validate_dataflow_path(dp, guard_repo)
        assert "String-theory prescreen" not in result.reasoning

    def test_prescreen_crash_degrades_to_normal_flow(self, guard_repo):
        llm = MagicMock()
        v = DataflowValidator(llm)
        with patch(
            "core.dataflow.injection_prescreen.prescreen_finding",
            side_effect=RuntimeError("boom"),
        ), patch.object(
            v, "_extract_path_conditions", return_value=([], {}),
        ), patch(
            "packages.codeql.dataflow_validator.check_path_feasibility_dual",
            return_value=PathSMTResult(
                feasible=False, reasoning="stub", satisfied=[], unknown=[], unsatisfied=[],
                smt_available=True, model={},
            ),
        ):
            result = v.validate_dataflow_path(_dataflow(), guard_repo)
        assert result is not None
        assert "String-theory prescreen" not in result.reasoning

    def test_nonexistent_repo_no_signal(self):
        # Unreadable sources (the pre-existing test fixtures' repo
        # path) must never produce a refutation.
        llm = MagicMock()
        v = DataflowValidator(llm)
        with patch.object(
            v, "_extract_path_conditions", return_value=([], {}),
        ), patch(
            "packages.codeql.dataflow_validator.check_path_feasibility_dual",
            return_value=PathSMTResult(
                feasible=False, reasoning="stub", satisfied=[], unknown=[], unsatisfied=[],
                smt_available=True, model={},
            ),
        ):
            result = v.validate_dataflow_path(
                _dataflow(), Path("/nonexistent-repo"),
            )
        assert "String-theory prescreen" not in result.reasoning

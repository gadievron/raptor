"""The dataflow validator's injection-prescreen hook.

A refuted finding must short-circuit BEFORE any LLM call (including
the path-condition extraction), demoted exactly like an SMT-unsat
verdict; no signal or a prescreen crash must leave the normal flow
untouched.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("z3")

from packages.codeql.dataflow_validator import (
    SMT_INFEASIBLE_CONFIDENCE,
    DataflowPath,
    DataflowStep,
    DataflowValidator,
)

# The refuting charset is DOTLESS: '.' is a pathtrav danger char ('.'
# builds '..' segments), so dot-admitting charsets must decline.
GUARD_APP = """\
import os
import re


def handler(request):
    name = request.args.get('name')
    if not re.match(r'^[A-Za-z0-9_+-]+$', name):
        return None
    cfg = os.path.join('/etc/app', name)
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
    def test_refutation_short_circuits_before_llm(self, guard_repo):
        llm = _exploding_llm()
        v = DataflowValidator(llm)
        result = v.validate_dataflow_path(_dataflow(), guard_repo)
        assert result.is_exploitable is False
        assert result.confidence == SMT_INFEASIBLE_CONFIDENCE
        assert "String-theory prescreen" in result.reasoning
        assert any("charset validator at app.py:7" in b
                   for b in result.barriers)
        assert result.smt_paths_checked == 1
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
            "packages.codeql.dataflow_validator.check_path_feasibility",
            return_value=SimpleNamespace(
                feasible=False, reasoning="stub", unsatisfied=[],
                smt_available=True, model=None,
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
            "packages.codeql.dataflow_validator.check_path_feasibility",
            return_value=SimpleNamespace(
                feasible=False, reasoning="stub", unsatisfied=[],
                smt_available=True, model=None,
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
            "packages.codeql.dataflow_validator.check_path_feasibility",
            return_value=SimpleNamespace(
                feasible=False, reasoning="stub", unsatisfied=[],
                smt_available=True, model=None,
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
            "packages.codeql.dataflow_validator.check_path_feasibility",
            return_value=SimpleNamespace(
                feasible=False, reasoning="stub", unsatisfied=[],
                smt_available=True, model=None,
            ),
        ):
            result = v.validate_dataflow_path(
                _dataflow(), Path("/nonexistent-repo"),
            )
        assert "String-theory prescreen" not in result.reasoning

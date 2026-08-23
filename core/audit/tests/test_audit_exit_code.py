"""Exit-code semantics for `raptor-audit run`.

A budget/time stop is a COMPLETED run with a stop reason: outcomes are
journalled, the report is written, and the lifecycle records
status=completed. Pre-fix the process still exited 1 for it,
contradicting the lifecycle status. Exit 0 now covers the completed
stop reasons; nonzero stays reserved for errors.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[3] / "libexec" / "raptor-audit"


@pytest.fixture(scope="module")
def audit_cli():
    """Import the raptor-audit script as a module (trust marker set)."""
    import os

    prior = os.environ.get("_RAPTOR_TRUSTED")
    os.environ["_RAPTOR_TRUSTED"] = "1"
    try:
        spec = importlib.util.spec_from_loader(
            "raptor_audit_cli",
            importlib.machinery.SourceFileLoader(
                "raptor_audit_cli", str(_SCRIPT),
            ),
        )
        mod = importlib.util.module_from_spec(spec)
        sys.modules["raptor_audit_cli"] = mod
        spec.loader.exec_module(mod)
        yield mod
    finally:
        sys.modules.pop("raptor_audit_cli", None)
        if prior is None:
            os.environ.pop("_RAPTOR_TRUSTED", None)
        else:
            os.environ["_RAPTOR_TRUSTED"] = prior


class TestExitCodeSemantics:
    def test_clean_completion_exits_zero(self, audit_cli):
        assert audit_cli._exit_code_for("complete") == 0

    def test_budget_stop_is_a_completed_run(self, audit_cli):
        # The observed contradiction: lifecycle status "completed"
        # with process exit code 1 on a budget stop.
        assert audit_cli._exit_code_for("llm_budget_exceeded") == 0
        assert audit_cli._exit_code_for("max_cost_usd") == 0

    def test_time_stop_is_a_completed_run(self, audit_cli):
        assert audit_cli._exit_code_for("max_seconds") == 0

    def test_errors_stay_nonzero(self, audit_cli):
        assert audit_cli._exit_code_for("no_checklist") == 1
        assert audit_cli._exit_code_for("shutdown") == 1
        assert audit_cli._exit_code_for("anything_else") == 1

"""`raptor-audit resume --max-cost` — per-segment cost-cap override.

Resume already accepted per-segment `--max-time` / `--max-workers`
overrides; the cost cap had no equivalent, so lifting a cap mid-run
forced abandoning the run. The override follows the same contract:
THIS segment only, persisted run config untouched, and `0` removes the
cap (``None`` is the downstream "no cap" representation — a literal
0.0 would read as an exhausted budget, the opposite intent).
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import argparse

import pytest

from core.audit.resume import remaining_budget_usd

_SCRIPT = Path(__file__).resolve().parents[3] / "libexec" / "raptor-audit"


@pytest.fixture(scope="module")
def audit_cli():
    """Import the raptor-audit script as a module (trust marker set)."""
    prior = os.environ.get("_RAPTOR_TRUSTED")
    os.environ["_RAPTOR_TRUSTED"] = "1"
    try:
        spec = importlib.util.spec_from_loader(
            "raptor_audit_cli_max_cost",
            importlib.machinery.SourceFileLoader(
                "raptor_audit_cli_max_cost", str(_SCRIPT),
            ),
        )
        mod = importlib.util.module_from_spec(spec)
        sys.modules["raptor_audit_cli_max_cost"] = mod
        spec.loader.exec_module(mod)
        yield mod
    finally:
        sys.modules.pop("raptor_audit_cli_max_cost", None)
        if prior is None:
            os.environ.pop("_RAPTOR_TRUSTED", None)
        else:
            os.environ["_RAPTOR_TRUSTED"] = prior


class TestResumeCostCap:
    def test_no_override_keeps_original_cap(self, audit_cli):
        assert audit_cli._resume_cost_cap(
            None, {"max_cost_usd": 25.0}) == (25.0, False)

    def test_no_override_no_original_cap(self, audit_cli):
        assert audit_cli._resume_cost_cap(None, {}) == (None, False)

    def test_override_replaces_original_cap(self, audit_cli):
        assert audit_cli._resume_cost_cap(
            50.0, {"max_cost_usd": 10.0}) == (50.0, True)

    def test_override_on_uncapped_run_adds_a_cap(self, audit_cli):
        assert audit_cli._resume_cost_cap(5.0, {}) == (5.0, True)

    def test_zero_removes_the_cap(self, audit_cli):
        # None is the "no cap" representation downstream; a literal
        # 0.0 cap would instead read as exhausted (finalize-only).
        assert audit_cli._resume_cost_cap(
            0.0, {"max_cost_usd": 10.0}) == (None, True)

    def test_segment_budget_honors_the_override(self, audit_cli):
        # The config-assembly composition cmd_resume performs: the
        # segment's max_cost_usd is remaining_budget_usd(cap, booked)
        # with the override cap in force — a raised cap over booked
        # spend yields the raised remainder.
        cap, overridden = audit_cli._resume_cost_cap(
            50.0, {"max_cost_usd": 10.0})
        assert overridden
        assert remaining_budget_usd(cap, 30.0) == 20.0

    def test_removed_cap_yields_uncapped_segment(self, audit_cli):
        cap, _ = audit_cli._resume_cost_cap(0.0, {"max_cost_usd": 10.0})
        assert remaining_budget_usd(cap, 30.0) is None


class TestMaxCostResumeArg:
    def test_accepts_positive(self, audit_cli):
        assert audit_cli._max_cost_resume_arg("12.5") == 12.5

    def test_accepts_zero(self, audit_cli):
        assert audit_cli._max_cost_resume_arg("0") == 0.0

    def test_rejects_negative(self, audit_cli):
        with pytest.raises(argparse.ArgumentTypeError):
            audit_cli._max_cost_resume_arg("-1")

    def test_rejects_non_float(self, audit_cli):
        with pytest.raises(argparse.ArgumentTypeError):
            audit_cli._max_cost_resume_arg("uncap")

    @pytest.mark.parametrize("spelling", ["nan", "inf", "-inf", "Infinity"])
    def test_rejects_non_finite(self, audit_cli, spelling):
        # float() accepts these spellings; nan would then pass every
        # remaining-budget comparison (effectively uncapped, behind a
        # "$nan" banner) and inf is 0-spelled-dishonestly — both are
        # refused at parse time.
        with pytest.raises(argparse.ArgumentTypeError):
            audit_cli._max_cost_resume_arg(spelling)


@pytest.mark.slow
class TestResumeParserAcceptsMaxCost:
    def test_flag_parses_and_reaches_the_command(self, tmp_path: Path):
        # A parsed flag reaches cmd_resume, which then refuses the
        # non-run directory with its own error (exit 1) — an unknown
        # flag would be an argparse refusal (exit 2) before any
        # command logic runs.
        env = dict(os.environ, _RAPTOR_TRUSTED="1")
        cp = subprocess.run(
            [sys.executable, str(_SCRIPT), "resume", str(tmp_path),
             "--max-cost", "25"],
            capture_output=True, text=True, env=env, timeout=120,
            check=False,
        )
        assert cp.returncode == 1, cp.stderr
        assert "error:" in cp.stderr

    def test_negative_value_refused_at_parse_time(self, tmp_path: Path):
        env = dict(os.environ, _RAPTOR_TRUSTED="1")
        cp = subprocess.run(
            [sys.executable, str(_SCRIPT), "resume", str(tmp_path),
             "--max-cost", "-3"],
            capture_output=True, text=True, env=env, timeout=120,
            check=False,
        )
        assert cp.returncode == 2
        assert "--max-cost must be a finite value >= 0" in cp.stderr

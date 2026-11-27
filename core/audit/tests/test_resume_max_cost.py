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
import sys
from pathlib import Path
from unittest.mock import patch

import argparse

import pytest

from core.testing.module_registry import module_registry_scope
from core.testing.standalone_cli import run_standalone_cli

from core.audit.resume import remaining_budget_usd

_SCRIPT = Path(__file__).resolve().parents[3] / "libexec" / "raptor-audit"


@pytest.fixture(scope="module")
def audit_cli():
    """Import the raptor-audit script as a module (trust marker set)."""
    with pytest.MonkeyPatch.context() as state:
        state.setenv("_RAPTOR_TRUSTED", "1")
        with module_registry_scope("raptor_audit_cli_max_cost") as modules:
            spec = importlib.util.spec_from_loader(
                "raptor_audit_cli_max_cost",
                importlib.machinery.SourceFileLoader(
                    "raptor_audit_cli_max_cost", str(_SCRIPT),
                ),
            )
            mod = importlib.util.module_from_spec(spec)
            modules["raptor_audit_cli_max_cost"] = mod
            with patch.object(sys, "path", sys.path.copy()):
                spec.loader.exec_module(mod)
            yield mod


def _stamped(cfg: dict, out_dir: Path) -> dict:
    """The run-path persistence shape: cap stamped for *out_dir*."""
    from core.run.resume_state_provenance import stamp_cost_cap
    stamp_cost_cap(cfg, out_dir)
    return cfg


class TestResumeCostCap:
    def test_no_override_keeps_original_cap(self, audit_cli, tmp_path):
        assert audit_cli._resume_cost_cap(
            None, {"max_cost_usd": 25.0}, tmp_path) == (25.0, False)

    def test_no_override_no_original_cap(self, audit_cli, tmp_path,
                                         capsys):
        # An absent cap with no stamp is unverifiable "uncapped" — the
        # exact rewrite shape (delete the key) — so it clamps to the
        # conservative default instead of resuming uncapped.
        assert audit_cli._resume_cost_cap(
            None, {}, tmp_path) == (50.0, False)
        assert "no valid provenance stamp" in capsys.readouterr().out

    def test_override_replaces_original_cap(self, audit_cli, tmp_path):
        assert audit_cli._resume_cost_cap(
            50.0, {"max_cost_usd": 10.0}, tmp_path) == (50.0, True)

    def test_override_on_uncapped_run_adds_a_cap(self, audit_cli,
                                                 tmp_path):
        assert audit_cli._resume_cost_cap(5.0, {}, tmp_path) == (5.0, True)

    def test_zero_removes_the_cap(self, audit_cli, tmp_path):
        # None is the "no cap" representation downstream; a literal
        # 0.0 cap would instead read as exhausted (finalize-only).
        assert audit_cli._resume_cost_cap(
            0.0, {"max_cost_usd": 10.0}, tmp_path) == (None, True)

    def test_segment_budget_honors_the_override(self, audit_cli,
                                                tmp_path):
        # The config-assembly composition cmd_resume performs: the
        # segment's max_cost_usd is remaining_budget_usd(cap, booked)
        # with the override cap in force — a raised cap over booked
        # spend yields the raised remainder.
        cap, overridden = audit_cli._resume_cost_cap(
            50.0, {"max_cost_usd": 10.0}, tmp_path)
        assert overridden
        assert remaining_budget_usd(cap, 30.0) == 20.0

    def test_removed_cap_yields_uncapped_segment(self, audit_cli,
                                                 tmp_path):
        cap, _ = audit_cli._resume_cost_cap(
            0.0, {"max_cost_usd": 10.0}, tmp_path)
        assert remaining_budget_usd(cap, 30.0) is None


class TestMaxCostArg:
    def test_accepts_positive(self, audit_cli):
        assert audit_cli._max_cost_arg("12.5") == 12.5

    def test_accepts_zero(self, audit_cli):
        assert audit_cli._max_cost_arg("0") == 0.0

    def test_rejects_negative(self, audit_cli):
        with pytest.raises(argparse.ArgumentTypeError):
            audit_cli._max_cost_arg("-1")

    def test_rejects_non_float(self, audit_cli):
        with pytest.raises(argparse.ArgumentTypeError):
            audit_cli._max_cost_arg("uncap")

    @pytest.mark.parametrize("spelling", ["nan", "inf", "-inf", "Infinity"])
    def test_rejects_non_finite(self, audit_cli, spelling):
        # float() accepts these spellings; nan would then pass every
        # remaining-budget comparison (effectively uncapped, behind a
        # "$nan" banner) and inf is 0-spelled-dishonestly — both are
        # refused at parse time.
        with pytest.raises(argparse.ArgumentTypeError):
            audit_cli._max_cost_arg(spelling)


@pytest.mark.slow
class TestResumeParserAcceptsMaxCost:
    def test_flag_parses_and_reaches_the_command(self, tmp_path: Path):
        # A parsed flag reaches cmd_resume, which then refuses the
        # non-run directory with its own error (exit 1) — an unknown
        # flag would be an argparse refusal (exit 2) before any
        # command logic runs.
        env = dict(os.environ, _RAPTOR_TRUSTED="1")
        cp = run_standalone_cli(
            [sys.executable, str(_SCRIPT), "resume", str(tmp_path),
             "--max-cost", "25"],
            capture_output=True, text=True, env=env, timeout=120,
            check=False,
        )
        assert cp.returncode == 1, cp.stderr
        assert "error:" in cp.stderr

    def test_negative_value_refused_at_parse_time(self, tmp_path: Path):
        env = dict(os.environ, _RAPTOR_TRUSTED="1")
        cp = run_standalone_cli(
            [sys.executable, str(_SCRIPT), "resume", str(tmp_path),
             "--max-cost", "-3"],
            capture_output=True, text=True, env=env, timeout=120,
            check=False,
        )
        assert cp.returncode == 2
        assert "--max-cost must be a finite value >= 0" in cp.stderr


class TestPersistedCapReadBack:
    """The persisted run-config cap is re-validated on read-back.

    The run config is a plain JSON file: a non-finite cap recorded by
    an older install (the run parser used a bare ``type=float``) or a
    hand edit must not silently resume as an uncapped segment — nan is
    truthy, so it presents as an active cap while every remaining-
    budget comparison against it is False.
    """

    @pytest.mark.parametrize(
        "poisoned", [float("nan"), float("inf"), float("-inf"), -5.0, "uncap"],
    )
    def test_poisoned_persisted_cap_is_refused(self, audit_cli, poisoned,
                                               tmp_path):
        with pytest.raises(ValueError, match="persisted max_cost_usd"):
            audit_cli._resume_cost_cap(
                None, {"max_cost_usd": poisoned}, tmp_path)

    @pytest.mark.parametrize(
        "poisoned", [float("nan"), float("inf"), -5.0],
    )
    def test_poisoned_cap_is_refused_even_when_stamped(
            self, audit_cli, poisoned, tmp_path):
        # Validation precedes verification: a stamp proves WHO wrote
        # the value, not that the value is sane.
        cfg = _stamped({"max_cost_usd": poisoned}, tmp_path)
        with pytest.raises(ValueError, match="persisted max_cost_usd"):
            audit_cli._resume_cost_cap(None, cfg, tmp_path)

    def test_explicit_override_bypasses_a_poisoned_config(self, audit_cli,
                                                          tmp_path):
        # The documented escape hatch: --max-cost on the resume
        # invocation never consults the persisted value.
        assert audit_cli._resume_cost_cap(
            12.0, {"max_cost_usd": float("nan")}, tmp_path) == (12.0, True)

    def test_valid_persisted_cap_still_reads_back(self, audit_cli,
                                                  tmp_path):
        assert audit_cli._resume_cost_cap(
            None, {"max_cost_usd": 25}, tmp_path) == (25.0, False)


@pytest.mark.slow
class TestRunParserValidatesMaxCost:
    @pytest.mark.parametrize("spelling", ["nan", "inf", "-3"])
    def test_non_finite_or_negative_cap_refused_at_parse_time(
            self, tmp_path: Path, spelling: str):
        # Parse-time refusal is exit 2; on an unvalidated parser the
        # value would reach cmd_run, which refuses the missing target
        # with exit 1 — by then a nan cap has already been accepted.
        env = dict(os.environ, _RAPTOR_TRUSTED="1")
        cp = run_standalone_cli(
            [sys.executable, str(_SCRIPT), "run",
             str(tmp_path / "missing-target"),
             "--max-cost", spelling],
            capture_output=True, text=True, env=env, timeout=120,
            check=False,
        )
        assert cp.returncode == 2, cp.stderr
        assert "--max-cost must be a finite value >= 0" in cp.stderr


class TestZeroCapSemantics:
    """``0`` means "remove the cap" on BOTH paths, and says so.

    An operator typing a zero cap may mean "spend nothing" — no cap
    value expresses that, so the run path must warn loudly instead of
    silently reinterpreting. A legacy run config that persisted 0.0
    reads back as None: the original run was uncapped, and a literal
    0.0 would instead hit remaining_budget_usd's exhausted clamp.
    """

    def test_stamped_persisted_zero_reads_back_uncapped(self, audit_cli,
                                                        tmp_path):
        # The legacy-0 → uncapped mapping survives ONLY behind a valid
        # provenance stamp: the run path genuinely persisted 0.
        cfg = _stamped({"max_cost_usd": 0.0}, tmp_path)
        assert audit_cli._resume_cost_cap(
            None, cfg, tmp_path) == (None, False)

    def test_unverified_persisted_zero_clamps(self, audit_cli, tmp_path,
                                              capsys):
        # Without a stamp, "0 = uncapped" is exactly the rewrite an
        # attacker with run-dir write access would make — it clamps to
        # the conservative default instead.
        assert audit_cli._resume_cost_cap(
            None, {"max_cost_usd": 0.0}, tmp_path) == (50.0, False)
        out = capsys.readouterr().out
        assert "0 (legacy uncapped)" in out
        assert "no valid provenance stamp" in out

    @pytest.mark.slow
    def test_run_zero_cap_warns_uncapped(self, tmp_path: Path):
        # Parse accepts 0 and cmd_run then refuses the missing target
        # (exit 1) — but only after the uncapped warning has printed.
        env = dict(os.environ, _RAPTOR_TRUSTED="1")
        cp = run_standalone_cli(
            [sys.executable, str(_SCRIPT), "run",
             str(tmp_path / "missing-target"),
             "--max-cost", "0"],
            capture_output=True, text=True, env=env, timeout=120,
            check=False,
        )
        assert cp.returncode == 1, cp.stderr
        assert "UNCAPPED" in cp.stderr
        assert "--max-cost 0 removes the cap" in cp.stderr


class TestCapProvenance:
    """The persisted cap is honored as-written only when its stamp
    verifies for THIS run dir; every unverified shape — missing,
    tampered, replayed into another run dir — degrades to the
    conservative default (never an error, never uncapped).
    """

    def test_stamped_large_cap_honored(self, audit_cli, tmp_path, capsys):
        cfg = _stamped({"max_cost_usd": 400.0}, tmp_path)
        assert audit_cli._resume_cost_cap(
            None, cfg, tmp_path) == (400.0, False)
        assert capsys.readouterr().out == ""

    def test_stamped_uncapped_honored(self, audit_cli, tmp_path, capsys):
        cfg = _stamped({}, tmp_path)
        assert audit_cli._resume_cost_cap(
            None, cfg, tmp_path) == (None, False)
        assert capsys.readouterr().out == ""

    def test_tampered_value_clamps(self, audit_cli, tmp_path, capsys):
        # Stamp minted over 10.0, value rewritten to 400.0: the token
        # no longer covers the value — clamp, with the banner naming
        # the remedy.
        cfg = _stamped({"max_cost_usd": 10.0}, tmp_path)
        cfg["max_cost_usd"] = 400.0
        assert audit_cli._resume_cost_cap(
            None, cfg, tmp_path) == (50.0, False)
        out = capsys.readouterr().out
        assert "$400.00" in out
        assert "--max-cost" in out

    def test_tampered_to_absent_clamps(self, audit_cli, tmp_path, capsys):
        # Deleting the cap key does not verify either: the stamp binds
        # the recorded VALUE, including "none".
        cfg = _stamped({"max_cost_usd": 10.0}, tmp_path)
        del cfg["max_cost_usd"]
        assert audit_cli._resume_cost_cap(
            None, cfg, tmp_path) == (50.0, False)
        assert "none (uncapped)" in capsys.readouterr().out

    def test_unverified_large_cap_clamps(self, audit_cli, tmp_path,
                                         capsys):
        assert audit_cli._resume_cost_cap(
            None, {"max_cost_usd": 400.0}, tmp_path) == (50.0, False)
        assert "no valid provenance stamp" in capsys.readouterr().out

    def test_unverified_tight_cap_honored_silently(self, audit_cli,
                                                   tmp_path, capsys):
        # Lowering a budget gains an attacker nothing: an unverified
        # cap at or under the default applies as-is, no banner.
        assert audit_cli._resume_cost_cap(
            None, {"max_cost_usd": 5.0}, tmp_path) == (5.0, False)
        assert capsys.readouterr().out == ""

    def test_stamp_is_bound_to_the_run_dir(self, audit_cli, tmp_path,
                                           capsys):
        # A stamped-uncapped config replayed into ANOTHER run dir is a
        # durable budget grant — the binding makes it unverified there.
        dir_a = tmp_path / "a"
        dir_b = tmp_path / "b"
        dir_a.mkdir()
        dir_b.mkdir()
        cfg = _stamped({}, dir_a)
        assert audit_cli._resume_cost_cap(None, cfg, dir_a) == (None, False)
        assert audit_cli._resume_cost_cap(None, cfg, dir_b) == (50.0, False)
        assert "no valid provenance stamp" in capsys.readouterr().out

    def test_cli_override_needs_no_stamp(self, audit_cli, tmp_path,
                                         capsys):
        # The operator's own flag is the escape hatch for every
        # unverified shape, including uncapping.
        assert audit_cli._resume_cost_cap(
            0.0, {"max_cost_usd": 400.0}, tmp_path) == (None, True)
        assert capsys.readouterr().out == ""

"""Tests for the raptor.py lifecycle dispatcher's per-mode argv handling.

Covers:
  1. ``_forward_max_cost_args`` — --max-cost-usd is re-injected only
     for children whose argparse defines the flag (two-direction:
     agentic still receives it; scan/codeql/fuzz/web never do), plus
     a drift guard that the allowlist matches what the child scripts
     actually define.
  2. ``_resolve_estimate_model`` — the pre-flight cost gate prices
     the estimate with the run's own --model selection or the
     configured primary, not a fixed provider default.
  3. fuzz standalone corpus modes — --export-seed-corpus /
     --prepare-corpus bypass the run lifecycle entirely (two-direction:
     a normal fuzz argv still goes through the lifecycle wrapper).
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

_RAPTOR_ROOT = Path(__file__).resolve().parents[3]


def _import_raptor():
    if "raptor" not in sys.modules:
        sys.path.insert(0, str(_RAPTOR_ROOT))
    import raptor
    return raptor


# ---------------------------------------------------------------------------
# _forward_max_cost_args
# ---------------------------------------------------------------------------


class TestForwardMaxCost:
    def test_agentic_child_receives_the_flag(self):
        raptor = _import_raptor()
        out = raptor._forward_max_cost_args(
            "agentic", ["--repo", "/x"], 12.5,
        )
        assert out == ["--repo", "/x", "--max-cost-usd", "12.5"]

    def test_other_modes_never_receive_the_flag(self):
        raptor = _import_raptor()
        for command in ("scan", "codeql", "fuzz", "web"):
            out = raptor._forward_max_cost_args(
                command, ["--repo", "/x"], 12.5,
            )
            assert "--max-cost-usd" not in out, command

    def test_no_cap_leaves_args_untouched(self):
        raptor = _import_raptor()
        args = ["--repo", "/x"]
        assert raptor._forward_max_cost_args("agentic", args, None) == args

    def test_allowlist_matches_child_parsers(self):
        """Drift guard: a mode belongs in _MAX_COST_FORWARD_COMMANDS
        exactly when its child script defines --max-cost-usd."""
        raptor = _import_raptor()
        child_scripts = {
            "scan": _RAPTOR_ROOT / "packages/static-analysis/scanner.py",
            "agentic": _RAPTOR_ROOT / "raptor_agentic.py",
            "codeql": _RAPTOR_ROOT / "raptor_codeql.py",
            "fuzz": _RAPTOR_ROOT / "raptor_fuzzing.py",
            "web": _RAPTOR_ROOT / "packages/web/scanner.py",
        }
        for command, script in child_scripts.items():
            defines = '"--max-cost-usd"' in script.read_text(encoding="utf-8")
            in_allowlist = command in raptor._MAX_COST_FORWARD_COMMANDS
            assert defines == in_allowlist, (
                f"{command}: child defines flag={defines}, "
                f"allowlisted={in_allowlist}"
            )


# ---------------------------------------------------------------------------
# _resolve_estimate_model
# ---------------------------------------------------------------------------


class TestResolveEstimateModel:
    def test_explicit_model_space_form_wins(self):
        raptor = _import_raptor()
        model = raptor._resolve_estimate_model(
            ["--repo", "/x", "--model", "gemini-2.5-pro"],
        )
        assert model == "gemini-2.5-pro"

    def test_explicit_model_equals_form_wins(self):
        raptor = _import_raptor()
        model = raptor._resolve_estimate_model(["--model=gpt-5"])
        assert model == "gpt-5"

    def test_configured_primary_used_when_no_model_arg(self):
        raptor = _import_raptor()
        fake = SimpleNamespace(model_name="my-configured-primary")
        with patch("core.llm.config._get_default_primary_model",
                   return_value=fake):
            assert raptor._resolve_estimate_model([]) == "my-configured-primary"

    def test_falls_back_to_anthropic_default_when_unresolvable(self):
        raptor = _import_raptor()
        from core.llm.model_data import PROVIDER_DEFAULT_MODELS
        with patch("core.llm.config._get_default_primary_model",
                   side_effect=RuntimeError("no config")):
            model = raptor._resolve_estimate_model(None)
        assert model == PROVIDER_DEFAULT_MODELS.get("anthropic", "")

    def test_gate_accepts_child_args_kwarg(self):
        # target=None short-circuits before any scorecard read: the
        # kwarg must be part of the shared gate signature so the
        # lifecycle wrapper can pass the run's argv.
        raptor = _import_raptor()
        fired = raptor._preflight_cost_gate(
            None, 10.0, Path("/nonexistent"), child_args=["--model", "x"],
        )
        assert fired is False


# ---------------------------------------------------------------------------
# fuzz standalone corpus modes bypass the lifecycle
# ---------------------------------------------------------------------------


class TestFuzzStandaloneBypassesLifecycle:
    def test_is_fuzz_standalone_truth_table(self):
        raptor = _import_raptor()
        assert raptor._is_fuzz_standalone(["--export-seed-corpus", "/d"])
        assert raptor._is_fuzz_standalone(["--prepare-corpus=/proj"])
        assert not raptor._is_fuzz_standalone(["--binary", "/x"])
        assert not raptor._is_fuzz_standalone([])

    def test_standalone_mode_skips_lifecycle(self):
        raptor = _import_raptor()
        with patch.object(raptor, "_run_script", return_value=0) as run_script, \
                patch.object(raptor, "_run_with_lifecycle") as lifecycle:
            rc = raptor.mode_fuzz(["--export-seed-corpus", "/tmp/seeds"])
        assert rc == 0
        assert run_script.called
        assert not lifecycle.called

    def test_normal_fuzz_still_uses_lifecycle(self):
        raptor = _import_raptor()
        with patch.object(raptor, "_run_script", return_value=0) as run_script, \
                patch.object(raptor, "_run_with_lifecycle",
                             return_value=0) as lifecycle:
            rc = raptor.mode_fuzz(["--binary", "/x"])
        assert rc == 0
        assert lifecycle.called
        assert not run_script.called

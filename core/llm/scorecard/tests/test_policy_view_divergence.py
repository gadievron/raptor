"""The CLI policy column vs the live gate.

``should_short_circuit`` is the live gate; the CLI re-derives a policy
column from the on-disk snapshot. Two divergence axes were silent:

* the live gate applies ``scorecard_freshness_half_life_days`` from
  the run's config, while the CLI's default view is unweighted — an
  operator auditing exactly this decision saw a different verdict
  than the routing their runs apply, with no breadcrumb;
* the CLI helper hardcoded its own copies of the Wilson gate
  parameters instead of the substrate's constants.

The CLI cannot read a run's in-process config, so the fix is honesty:
the gate parameters come from the ONE substrate definition, the
default view carries a one-line unweighted-view note, and ``summary``
gains the same ``--freshness`` lens the other views already had.
"""

from __future__ import annotations

import ast
import json
import pathlib
from datetime import datetime, timedelta, timezone

from core.llm.scorecard.scorecard import ModelScorecard

CLI_PATH = pathlib.Path(__file__).resolve().parents[1] / "cli.py"


def _backdated_sidecar(tmp_path) -> pathlib.Path:
    """20 correct cheap-tier events, backdated ~12 months: unweighted
    they Wilson-gate to fall-through; under a 30d half-life the
    effective n collapses below the floor to learning — the probe
    shape for the divergence."""
    path = tmp_path / "sc.json"
    sc = ModelScorecard(path)
    for _ in range(20):
        sc.record_event("dc", "m", "cheap_short_circuit", "correct")
    raw = json.loads(path.read_text())
    cell = raw["models"]["m"]["dc"]
    buckets = cell["events"]["cheap_short_circuit"]
    old_bucket = (
        datetime.now(timezone.utc) - timedelta(days=365)
    ).strftime("%Y-%m")
    cell["events"]["cheap_short_circuit"] = {
        old_bucket: next(iter(buckets.values())),
    }
    raw.pop("integrity", None)
    path.write_text(json.dumps(raw))
    # Re-stamp through the sanctioned operator path.
    assert ModelScorecard(path).adopt_unverified() is True
    return path


def test_policy_helper_defaults_come_from_substrate_constants():
    """AST drift-guard: ``_policy_for_stats`` must default its gate
    parameters to the substrate's named constants, never re-hardcode
    them (they had drifted into independent literals once)."""
    tree = ast.parse(CLI_PATH.read_text(encoding="utf-8"))
    fn = next(
        node for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
        and node.name == "_policy_for_stats"
    )
    kwonly = {
        arg.arg: default
        for arg, default in zip(fn.args.kwonlyargs, fn.args.kw_defaults)
    }
    for param in ("sample_size_floor", "miss_rate_ceiling"):
        default = kwonly[param]
        assert isinstance(default, ast.Name), (
            f"_policy_for_stats {param} default must reference the "
            f"substrate constant, got {ast.dump(default)}"
        )


def test_list_default_view_carries_unweighted_note(tmp_path, capsys):
    from core.llm.scorecard.cli import main

    path = _backdated_sidecar(tmp_path)
    assert main(["--path", str(path), "list"]) == 0
    out = capsys.readouterr().out
    assert "unweighted" in out
    assert "--freshness" in out


def test_list_freshness_view_omits_the_note(tmp_path, capsys):
    from core.llm.scorecard.cli import main

    path = _backdated_sidecar(tmp_path)
    assert main(["--path", str(path), "list", "--freshness", "30"]) == 0
    out = capsys.readouterr().out
    assert "unweighted with default gate parameters" not in out


def test_summary_accepts_freshness_lens(tmp_path, capsys):
    from core.llm.scorecard.cli import main

    path = _backdated_sidecar(tmp_path)
    # Unweighted: the stale-but-plentiful cell is NOT learning.
    assert main(["--path", str(path), "summary"]) == 0
    unweighted = capsys.readouterr().out
    assert "1 learning" not in unweighted
    # Weighted at 30d: effective n collapses below the floor.
    assert main([
        "--path", str(path), "summary", "--freshness", "30",
    ]) == 0
    weighted = capsys.readouterr().out
    assert "1 learning" in weighted


def test_summary_matches_live_gate_under_same_freshness(tmp_path):
    from core.llm.scorecard.cli import _policy_for_stats

    path = _backdated_sidecar(tmp_path)
    live = ModelScorecard(
        path, freshness_half_life_days=30.0,
    ).should_short_circuit("dc", "m")
    stats = [
        s for s in ModelScorecard(path).get_stats(
            freshness_half_life_days=30.0,
        )
        if s.model == "m"
    ]
    assert _policy_for_stats(stats[0]) == live

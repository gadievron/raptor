"""Binary-analysis run-dir readers pay the shared default read budget.

``_load_replay_summary`` reads replay-summary.json through
``core.json.load_json`` with no site-specific budget, so it must
inherit the loader's capped-by-default contract: an oversized
artifact is refused and degrades to the site's own best-effort
empty-dict path, a normal one still flows. The budget is tightened
via the module constant (resolved per call) so the probe costs
kilobytes, not the real cap.
"""

import json
from pathlib import Path

import core.json.utils as json_utils
from packages.binary_analysis.fuzz_evidence import _load_replay_summary


def _tighten(monkeypatch, budget: int = 1024) -> None:
    monkeypatch.setattr(
        json_utils, "DEFAULT_JSON_MAX_BYTES", budget, raising=False,
    )


def _write_summary(fuzz_dir: Path, obj) -> None:
    (fuzz_dir / "replay-summary.json").write_text(
        json.dumps(obj), encoding="utf-8",
    )


def test_oversized_summary_refused(tmp_path, monkeypatch):
    _tighten(monkeypatch)
    _write_summary(
        tmp_path,
        {"crash-1": [{"verdict": "reproduced"}], "pad": ["x" * 4096]},
    )
    assert _load_replay_summary(tmp_path) == {}


def test_normal_summary_flows(tmp_path, monkeypatch):
    _tighten(monkeypatch)
    _write_summary(tmp_path, {"crash-1": [{"verdict": "reproduced"}]})
    assert _load_replay_summary(tmp_path) == {
        "crash-1": [{"verdict": "reproduced"}],
    }

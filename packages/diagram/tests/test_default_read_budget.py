"""Diagram run-dir readers pay the shared default read budget.

``attack_paths.generate_from_file`` reads attack-paths.json through
``core.json.load_json`` with no site-specific budget, so it must
inherit the loader's capped-by-default contract: an oversized
artifact is refused and surfaces through the site's own failed-load
error path, a normal one still renders. The budget is tightened via
the module constant (resolved per call) so the probe costs
kilobytes, not the real cap.
"""

import json

import pytest

import core.json.utils as json_utils
from packages.diagram.attack_paths import generate_from_file


def _tighten(monkeypatch, budget: int = 1024) -> None:
    monkeypatch.setattr(
        json_utils, "DEFAULT_JSON_MAX_BYTES", budget, raising=False,
    )


def test_oversized_attack_paths_refused(tmp_path, monkeypatch):
    _tighten(monkeypatch)
    ap = tmp_path / "attack-paths.json"
    ap.write_text(
        json.dumps({"paths": [], "pad": "x" * 4096}), encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Failed to load"):
        generate_from_file(ap)


def test_normal_attack_paths_flow(tmp_path, monkeypatch):
    _tighten(monkeypatch)
    ap = tmp_path / "attack-paths.json"
    ap.write_text(json.dumps({"paths": []}), encoding="utf-8")
    assert isinstance(generate_from_file(ap), str)

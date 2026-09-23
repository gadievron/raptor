"""Project run-dir readers pay the shared default read budget.

``run_is_imported`` reads the import marker through
``core.json.load_json`` with no site-specific budget, so it must
inherit the loader's capped-by-default contract: an oversized marker
is refused and degrades to "not imported" (the site's own
best-effort semantics), a normal marker still flows. The budget is
tightened via the module constant (resolved per call) so the probe
costs kilobytes, not the real cap.
"""

import json
from pathlib import Path

import core.json.utils as json_utils
from core.project.findings_utils import (
    IMPORTED_RUN_MARKER_FILE,
    run_is_imported,
)


def _tighten(monkeypatch, budget: int = 1024) -> None:
    monkeypatch.setattr(
        json_utils, "DEFAULT_JSON_MAX_BYTES", budget, raising=False,
    )


def _write_marker(run_dir: Path, obj: dict) -> None:
    (run_dir / IMPORTED_RUN_MARKER_FILE).write_text(
        json.dumps(obj), encoding="utf-8",
    )


def test_oversized_marker_refused(tmp_path, monkeypatch):
    _tighten(monkeypatch)
    _write_marker(tmp_path, {"imported": True, "pad": "x" * 4096})
    assert run_is_imported(tmp_path) is False


def test_normal_marker_flows(tmp_path, monkeypatch):
    _tighten(monkeypatch)
    _write_marker(tmp_path, {"imported": True})
    assert run_is_imported(tmp_path) is True

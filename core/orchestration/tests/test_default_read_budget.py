"""Orchestration run-dir readers pay the shared default read budget.

``_load_audit_findings`` reads a sibling run's findings.json through
``core.json.load_json`` with no site-specific budget, so it must
inherit the loader's capped-by-default contract: an oversized
artifact is refused and degrades to the site's own best-effort
empty-list path, a normal one still flows. The budget is tightened
via the module constant (resolved per call) so the probe costs
kilobytes, not the real cap.
"""

import json
from pathlib import Path

import core.json.utils as json_utils
from core.orchestration.agentic_passes import _load_audit_findings


def _tighten(monkeypatch, budget: int = 1024) -> None:
    monkeypatch.setattr(
        json_utils, "DEFAULT_JSON_MAX_BYTES", budget, raising=False,
    )


def _write_findings(audit_dir: Path, obj) -> None:
    (audit_dir / "findings.json").write_text(
        json.dumps(obj), encoding="utf-8",
    )


def test_oversized_findings_refused(tmp_path, monkeypatch):
    _tighten(monkeypatch)
    _write_findings(
        tmp_path,
        {"findings": [{"id": "f-1"}], "pad": "x" * 4096},
    )
    assert _load_audit_findings(tmp_path) == []


def test_normal_findings_flow(tmp_path, monkeypatch):
    _tighten(monkeypatch)
    _write_findings(tmp_path, {"findings": [{"id": "f-1"}]})
    assert _load_audit_findings(tmp_path) == [{"id": "f-1"}]

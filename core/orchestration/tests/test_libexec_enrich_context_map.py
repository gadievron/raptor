"""Tests for libexec/raptor-enrich-context-map's sink-discovery stage.

Regression: the script passed ``extra_sinks=`` to
``enrich_with_sink_discovery`` unconditionally.  On substrate
revisions whose signature has no such parameter the call raised
TypeError inside the stage's broad handler — sink enrichment
silently produced nothing on every run.  The script now passes the
kwarg only when the signature accepts it.

The script is executed in-process via runpy so the collaborating
modules can be monkeypatched (heavy enrichers stubbed out, the sink
substrate replaced with legacy/new-signature fakes).
"""

from __future__ import annotations

import json
import runpy
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "libexec" / "raptor-enrich-context-map"


@pytest.fixture
def understand_dir(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("def main():\n    pass\n",
                                   encoding="utf-8")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "context-map.json").write_text(
        json.dumps({"sinks": []}), encoding="utf-8")
    (run_dir / "checklist.json").write_text(
        json.dumps({"target_path": str(target), "files": []}),
        encoding="utf-8")
    return run_dir


def _stub_heavy_stages(monkeypatch):
    """Make every stage before sink discovery a fast no-op."""
    import core.orchestration.context_map_callgraph as cg
    import packages.source_intel as si
    from core.inventory import builder

    def _zero(*a, **kw):
        return 0

    def _raise(*a, **kw):
        raise RuntimeError("stubbed out in test")

    monkeypatch.setattr(cg, "enrich_with_call_edges", _zero)
    monkeypatch.setattr(cg, "enrich_with_forward_reachable", _zero)
    monkeypatch.setattr(builder, "build_inventory", _raise)
    monkeypatch.setattr(si, "analyze", _raise)


def _run(understand_dir, monkeypatch, sink_fn, iris_sinks=None):
    import core.iris.api as iris_api
    import core.orchestration.context_map_sinks as sinks_mod

    _stub_heavy_stages(monkeypatch)
    monkeypatch.setattr(sinks_mod, "enrich_with_sink_discovery", sink_fn)
    monkeypatch.setattr(
        iris_api, "get_project_sinks",
        lambda out_dir=None: iris_sinks or [],
    )
    monkeypatch.setenv("_RAPTOR_TRUSTED", "1")
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), str(understand_dir)])
    try:
        runpy.run_path(str(SCRIPT), run_name="__main__")
    except SystemExit as e:
        return e.code or 0
    return 0


class TestSinkStageSignatureCompat:
    def test_new_signature_receives_extra_sinks(
        self, understand_dir, monkeypatch,
    ):
        seen = {}

        def new_style(context_map, target_path, *, max_depth=6,
                      framework_threshold=3, framework_min_files=2,
                      extra_sinks=None):
            seen["extra_sinks"] = extra_sinks
            context_map["sinks"].append({"id": "from-test"})
            return 1

        code = _run(understand_dir, monkeypatch, new_style,
                    iris_sinks=["evil_sink"])
        assert code == 0
        assert seen["extra_sinks"] == ["evil_sink"]
        data = json.loads(
            (understand_dir / "context-map.json").read_text(encoding="utf-8"))
        assert {"id": "from-test"} in data["sinks"]

    def test_legacy_signature_still_enriches(
        self, understand_dir, monkeypatch,
    ):
        """Substrate without ``extra_sinks``: the stage must still run
        (regression — it used to TypeError into the broad handler)."""
        calls = []

        def legacy(context_map, target_path, *, max_depth=6,
                   framework_threshold=3, framework_min_files=2):
            calls.append(True)
            context_map["sinks"].append({"id": "legacy"})
            return 1

        code = _run(understand_dir, monkeypatch, legacy,
                    iris_sinks=["evil_sink"])
        assert code == 0
        assert calls, "sink stage never ran against the legacy substrate"
        data = json.loads(
            (understand_dir / "context-map.json").read_text(encoding="utf-8"))
        assert {"id": "legacy"} in data["sinks"]

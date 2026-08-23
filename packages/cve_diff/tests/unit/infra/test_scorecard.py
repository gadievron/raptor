"""Tests for the discovery-agent scorecard feed
(``cve_diff/infra/scorecard.py``) and its opt-in wiring through the
pipeline. The scorecard substrate itself is tested in
``core/llm/scorecard``; here we assert the producer contract: correct
cell, correct event type, mechanical adjudication only, and no writes
unless an entry point opted in.
"""

from __future__ import annotations

import pytest
from cve_diff.infra.scorecard import DECISION_CLASS, record_discovery_outcome


def test_records_correct_event_into_discovery_cell(tmp_path):
    from core.llm.scorecard.scorecard import ModelScorecard

    path = tmp_path / "llm_scorecard.json"
    sc = ModelScorecard(path)
    assert record_discovery_outcome(
        "claude-opus-4-7", "CVE-2024-1111", verified=True, scorecard=sc,
    )
    raw = path.read_text()
    assert DECISION_CLASS in raw
    assert "tool_evidence" in raw
    assert "claude-opus-4-7" in raw


def test_records_incorrect_event(tmp_path):
    from core.llm.scorecard.scorecard import ModelScorecard

    path = tmp_path / "llm_scorecard.json"
    sc = ModelScorecard(path)
    assert record_discovery_outcome(
        "gemini-2.5-pro", "CVE-2024-2222", verified=False, scorecard=sc,
    )
    assert '"incorrect": 1' in path.read_text()


def test_missing_model_skips_and_never_raises(tmp_path):
    assert record_discovery_outcome("", "CVE-2024-3333", verified=True) is False


def test_scorecard_errors_are_swallowed():
    class _Broken:
        def record_event(self, *a, **k):
            raise OSError("disk full")

    assert record_discovery_outcome(
        "m", "CVE-2024-4444", verified=True, scorecard=_Broken(),
    ) is False


def test_env_path_override_used_when_no_scorecard_passed(
    tmp_path, monkeypatch,
):
    path = tmp_path / "isolated_scorecard.json"
    monkeypatch.setenv("RAPTOR_SCORECARD_PATH", str(path))
    assert record_discovery_outcome("m-x", "CVE-2024-5555", verified=True)
    assert path.exists()
    assert DECISION_CLASS in path.read_text()


# ---------- pipeline wiring ----------


def _capture_recorder(monkeypatch):
    seen = []

    def _rec(model_id, cve_id, *, verified, scorecard=None):
        seen.append((model_id, cve_id, verified))
        return True

    monkeypatch.setattr(
        "cve_diff.infra.scorecard.record_discovery_outcome", _rec,
    )
    return seen


def _rescued_pipeline(tmp_path, monkeypatch, **pipeline_kw):
    """Pipeline with a stubbed rescued agent; _acquire_to_render is
    monkeypatched per test to simulate stage-2-5 verdicts."""
    from dataclasses import dataclass

    from cve_diff.agent.types import AgentOutput
    from cve_diff.core.models import CommitSha, PatchTuple
    from cve_diff.pipeline import Pipeline

    @dataclass
    class _StubAgent:
        def run(self, config, ctx):
            return AgentOutput(
                value=PatchTuple(
                    repository_url="https://github.com/example/proj",
                    fix_commit=CommitSha("a" * 40),
                    introduced=None,
                ),
                rationale="stub",
            )

    return Pipeline(agent=_StubAgent(), disk_limit_pct=99.9, **pipeline_kw)


def test_pipeline_records_correct_on_verified_pick(tmp_path, monkeypatch):
    seen = _capture_recorder(monkeypatch)
    pipeline = _rescued_pipeline(tmp_path, monkeypatch, scorecard_enabled=True)
    sentinel = object()
    monkeypatch.setattr(
        pipeline, "_acquire_to_render", lambda *a, **k: sentinel,
    )
    result = pipeline.run("CVE-2099-0001", tmp_path)
    assert result is sentinel
    assert seen == [("claude-opus-4-7", "CVE-2099-0001", True)]


def test_pipeline_records_incorrect_on_shape_refutation(
    tmp_path, monkeypatch,
):
    from cve_diff.core.exceptions import AnalysisError

    seen = _capture_recorder(monkeypatch)
    pipeline = _rescued_pipeline(
        tmp_path, monkeypatch, scorecard_enabled=True, model_id="m-y",
    )

    def _reject(*a, **k):
        raise AnalysisError("CVE-2099-0002: diff shape 'notes_only' rejected")

    monkeypatch.setattr(pipeline, "_acquire_to_render", _reject)
    with pytest.raises(AnalysisError):
        pipeline.run("CVE-2099-0002", tmp_path)
    # Two picks adjudicated: the original and the post-submit retry.
    assert seen == [
        ("m-y", "CVE-2099-0002", False),
        ("m-y", "CVE-2099-0002", False),
    ]


def test_pipeline_skips_recording_on_transient_failure(
    tmp_path, monkeypatch,
):
    from cve_diff.core.exceptions import AcquisitionError

    seen = _capture_recorder(monkeypatch)
    pipeline = _rescued_pipeline(tmp_path, monkeypatch, scorecard_enabled=True)

    def _transient(*a, **k):
        raise AcquisitionError("CVE-2099-0003: clone cascade failed")

    monkeypatch.setattr(pipeline, "_acquire_to_render", _transient)
    with pytest.raises(AcquisitionError):
        pipeline.run("CVE-2099-0003", tmp_path)
    assert seen == []


def test_pipeline_default_never_touches_scorecard(tmp_path, monkeypatch):
    seen = _capture_recorder(monkeypatch)
    pipeline = _rescued_pipeline(tmp_path, monkeypatch)  # opt-in absent
    monkeypatch.setattr(
        pipeline, "_acquire_to_render", lambda *a, **k: object(),
    )
    pipeline.run("CVE-2099-0004", tmp_path)
    assert seen == []

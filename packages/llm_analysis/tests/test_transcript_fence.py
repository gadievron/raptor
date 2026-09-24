"""Honesty fence: LLM-dispatch surfaces not yet transcript-adopted.

``orchestrate()`` (the /analyze --model / agentic parallel path) and
the ranking stage construct plain ``LLMClient``s outside the
record/replay seam. Under an active REPLAY session they must refuse —
proceeding would dispatch live (network + cost) while the operator
believes the run is hermetic. Under RECORD they proceed with a loud
under-recording warning. No fence when no transcript is active.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from core.llm.providers import LLMResponse  # noqa: E402
from core.llm.transcript import (  # noqa: E402
    TranscriptError,
    TranscriptRecorder,
    reset_active_transcript,
)


@pytest.fixture(autouse=True)
def _fresh_session(monkeypatch):
    monkeypatch.delenv("RAPTOR_LLM_TRANSCRIPT", raising=False)
    reset_active_transcript()
    yield
    reset_active_transcript()


def _seed_transcript(tmp_path: Path) -> Path:
    path = tmp_path / "t.jsonl"
    TranscriptRecorder(path).record_generate(
        "p", None, "analyse", {},
        LLMResponse(
            content="x", model="m", provider="anthropic",
            tokens_used=1, cost=0.0, finish_reason="stop",
        ),
    )
    return path


def _activate(monkeypatch, mode: str, path: Path) -> None:
    monkeypatch.setenv("RAPTOR_LLM_TRANSCRIPT", f"{mode}:{path}")
    reset_active_transcript()


class TestOrchestrateFence:
    def _call(self, tmp_path):
        from packages.llm_analysis.orchestrator import orchestrate
        return orchestrate(
            prep_report_path=tmp_path / "missing-report.json",
            repo_path=tmp_path,
            out_dir=tmp_path / "out",
        )

    def test_replay_refuses(self, tmp_path, monkeypatch):
        _activate(monkeypatch, "replay", _seed_transcript(tmp_path))
        with pytest.raises(TranscriptError, match="not transcript-adopted"):
            self._call(tmp_path)

    def test_record_warns_and_proceeds(self, tmp_path, monkeypatch, caplog):
        _activate(monkeypatch, "record", tmp_path / "t.jsonl")
        # Proceeds past the fence; then the missing Phase 3 report
        # aborts the run in the pre-existing way (None).
        with caplog.at_level("WARNING"):
            assert self._call(tmp_path) is None
        assert any(
            "outside the transcript seam" in rec.getMessage()
            for rec in caplog.records
        )

    def test_no_session_no_fence(self, tmp_path):
        # Baseline behaviour untouched: missing report returns None.
        assert self._call(tmp_path) is None


class TestRankStageFence:
    def _call(self):
        from packages.llm_analysis.rank_stage import (
            rank_findings_for_analysis,
        )
        cfg = MagicMock()
        cfg.primary_model = object()
        findings = [{"finding_id": f"F{i}"} for i in range(3)]
        return rank_findings_for_analysis(findings, cfg)

    def test_replay_refuses_outside_besteffort_net(
        self, tmp_path, monkeypatch,
    ):
        """The refusal must PROPAGATE — the stage's best-effort
        try/except would otherwise degrade it into a silent
        pass-through with a live client one branch later."""
        _activate(monkeypatch, "replay", _seed_transcript(tmp_path))
        with pytest.raises(TranscriptError, match="not transcript-adopted"):
            self._call()

    def test_record_warns(self, tmp_path, monkeypatch, caplog):
        _activate(monkeypatch, "record", tmp_path / "t.jsonl")
        with caplog.at_level("WARNING"):
            findings, cost, model = self._call()
        assert len(findings) == 3  # best-effort result shape intact
        assert any(
            "outside the transcript seam" in rec.getMessage()
            for rec in caplog.records
        )

"""Tests for core.llm.factory — the soft-fail client factory's
canonical home (moved from packages/llm_analysis, which re-exports).
"""

from __future__ import annotations

import core.llm.factory as factory_mod
from core.llm.factory import get_client


def test_llm_analysis_reexports_the_same_object():
    # The documented `from packages.llm_analysis import get_client`
    # surface must stay working AND stay the same function — a fork
    # here would be the exact drift this move ends.
    from packages.llm_analysis import get_client as legacy_get_client
    assert legacy_get_client is get_client


def test_returns_none_when_no_default_model(monkeypatch):
    monkeypatch.setattr(
        "core.llm.config._get_default_primary_model",
        lambda prefer=None: None,
    )
    assert get_client() is None


def test_soft_fails_on_construction_error(monkeypatch):
    class _Boom:
        def __init__(self, *a, **k):
            raise RuntimeError("no provider")

    class _Cfg:
        primary_model = object()  # truthy — reaches LLMClient()

    monkeypatch.setattr(factory_mod, "LLMClient", _Boom)
    assert get_client(config=_Cfg()) is None


def test_prefer_kwarg_forwarded(monkeypatch):
    seen = {}

    def _fake_default(prefer=None):
        seen["prefer"] = prefer

    monkeypatch.setattr(
        "core.llm.config._get_default_primary_model", _fake_default,
    )
    get_client(prefer="anthropic")
    assert seen["prefer"] == "anthropic"


class TestTranscriptRouting:
    """Transcript-session routing (core.llm.transcript adoption)."""

    def _seed_transcript(self, tmp_path):
        from core.llm.providers import LLMResponse
        from core.llm.transcript import TranscriptRecorder
        path = tmp_path / "t.jsonl"
        TranscriptRecorder(path).record_generate(
            "p", None, "analyse", {},
            LLMResponse(
                content="frozen", model="m", provider="anthropic",
                tokens_used=1, cost=0.0, finish_reason="stop",
            ),
        )
        return path

    def test_replay_mode_returns_client_without_any_provider(
        self, tmp_path, monkeypatch,
    ):
        from core.llm.transcript import (
            TranscriptLLMClient,
            reset_active_transcript,
        )
        path = self._seed_transcript(tmp_path)
        monkeypatch.setenv("RAPTOR_LLM_TRANSCRIPT", f"replay:{path}")
        monkeypatch.setattr(
            "core.llm.config._get_default_primary_model",
            lambda prefer=None: None,
        )
        reset_active_transcript()
        try:
            client = get_client()
            assert isinstance(client, TranscriptLLMClient)
            assert client.generate("p", task_type="analyse").content == \
                "frozen"
            assert client.providers == {}
        finally:
            reset_active_transcript()

    def test_garbled_transcript_env_is_loud_not_none(self, monkeypatch):
        from core.llm.transcript import (
            TranscriptError,
            reset_active_transcript,
        )
        import pytest as _pytest
        monkeypatch.setenv("RAPTOR_LLM_TRANSCRIPT", "garbled-value")
        reset_active_transcript()
        try:
            with _pytest.raises(TranscriptError):
                get_client()
        finally:
            reset_active_transcript()

    def test_record_mode_wraps_the_constructed_client(
        self, tmp_path, monkeypatch,
    ):
        from core.llm.config import LLMConfig, ModelConfig
        from core.llm.transcript import (
            TranscriptLLMClient,
            reset_active_transcript,
        )
        monkeypatch.setenv(
            "RAPTOR_LLM_TRANSCRIPT", f"record:{tmp_path / 't.jsonl'}",
        )
        reset_active_transcript()
        try:
            client = get_client(config=LLMConfig(
                primary_model=ModelConfig(
                    provider="anthropic", model_name="test-model-stub",
                    api_key="k",
                ),
                enable_caching=False,
            ))
            assert isinstance(client, TranscriptLLMClient)
            assert client.transcript_session.mode == "record"
        finally:
            reset_active_transcript()

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

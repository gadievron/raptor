"""The no-external-LLM transport banner prints once per process.

The claude-CLI transport constructs an LLMClient per call, so the
unguarded construction-time banner printed once per worker call — 12
copies on one observed run. It now goes through a process-level
once-guard like the model banner.
"""

from __future__ import annotations

import types

import core.llm.client as client_mod
from core.llm.client import LLMClient
from core.llm.config import LLMConfig, ModelConfig


def _availability():
    return types.SimpleNamespace(
        external_llm=False, claude_code=True, llm_available=True,
    )


def _config():
    return LLMConfig(
        primary_model=ModelConfig(
            provider="claudecode", model_name="sonnet", api_key="",
        ),
        enable_caching=False,
        enable_fallback=False,
    )


def _capture_infos(monkeypatch):
    lines: list[str] = []
    real_info = client_mod.logger.info

    def _sink(msg, *args, **kwargs):
        try:
            lines.append(str(msg) % args if args else str(msg))
        except (TypeError, ValueError):
            lines.append(str(msg))
        real_info(msg, *args, **kwargs)

    monkeypatch.setattr(client_mod.logger, "info", _sink)
    return lines


def test_transport_banner_prints_once_across_clients(monkeypatch):
    monkeypatch.setattr(client_mod, "_TRANSPORT_BANNER_SHOWN", False)
    monkeypatch.setattr(
        "core.llm.detection.detect_llm_availability",
        lambda: _availability(),
    )
    lines = _capture_infos(monkeypatch)

    for _ in range(12):   # one client per worker call, as observed
        LLMClient(_config())

    banners = [m for m in lines if "claude CLI" in m and "transport" in m]
    assert len(banners) == 1, banners


def test_transport_banner_guard_helper():
    client_mod._TRANSPORT_BANNER_SHOWN = False
    try:
        assert client_mod._transport_banner_shown() is False
        assert client_mod._transport_banner_shown() is True
        assert client_mod._transport_banner_shown() is True
    finally:
        client_mod._TRANSPORT_BANNER_SHOWN = False

"""Tests for the dispatcher→provider forwarding-leg timeout.

The upstream leg used to hardcode a 60s read timeout, killing any
non-streaming generation longer than a minute regardless of the
worker's configured per-model timeout (audit-sized structured reviews
measure 170s+; worker configs go up to 600s). The timeout is now
derived from ``RAPTOR_LLM_DISPATCHER_UPSTREAM_TIMEOUT_S`` with a
default that covers the largest worker-side timeout.
"""

from __future__ import annotations

import pytest

from core.llm.dispatcher.server import (
    _UPSTREAM_CONNECT_TIMEOUT_S,
    _UPSTREAM_DEFAULT_TIMEOUT_S,
    _upstream_timeout,
)


def test_default_covers_largest_worker_timeout(monkeypatch):
    """Without the env knob, the read timeout must be >= the largest
    per-model worker timeout (600s for claudecode/audit models)."""
    monkeypatch.delenv("RAPTOR_LLM_DISPATCHER_UPSTREAM_TIMEOUT_S", raising=False)
    t = _upstream_timeout()
    assert t.read >= 600.0
    assert t.read == float(_UPSTREAM_DEFAULT_TIMEOUT_S)


def test_connect_timeout_stays_short(monkeypatch):
    monkeypatch.delenv("RAPTOR_LLM_DISPATCHER_UPSTREAM_TIMEOUT_S", raising=False)
    t = _upstream_timeout()
    assert t.connect == _UPSTREAM_CONNECT_TIMEOUT_S


def test_env_override(monkeypatch):
    monkeypatch.setenv("RAPTOR_LLM_DISPATCHER_UPSTREAM_TIMEOUT_S", "120")
    t = _upstream_timeout()
    assert t.read == 120.0
    # connect timeout is not operator-tunable — stays short
    assert t.connect == _UPSTREAM_CONNECT_TIMEOUT_S


@pytest.mark.parametrize("bad", ["", "abc", "0", "-5"])
def test_invalid_env_falls_back_to_default(monkeypatch, bad):
    monkeypatch.setenv("RAPTOR_LLM_DISPATCHER_UPSTREAM_TIMEOUT_S", bad)
    t = _upstream_timeout()
    assert t.read == float(_UPSTREAM_DEFAULT_TIMEOUT_S)

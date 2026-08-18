"""Tests for the upstream-proxy handshake timeout knob.

The upstream leg (TCP connect to the corporate proxy + CONNECT
negotiation) used to share the fixed 10s per-IO budget. Slow,
authenticated, or loaded corporate proxies can legitimately exceed
that, and every resulting 502 costs the caller a full SDK retry
cycle. ``RAPTOR_PROXY_UPSTREAM_HANDSHAKE_TIMEOUT_S`` widens ONLY the
handshake budget; the per-IO read budget keeps failing fast.
"""

from __future__ import annotations

import pytest

from core.sandbox import proxy as proxy_mod
from core.sandbox.proxy import (
    _PROXY_READ_TIMEOUT_S,
    _upstream_handshake_timeout,
)


@pytest.fixture
def reset_proxy():
    proxy_mod._reset_for_tests()
    yield
    proxy_mod._reset_for_tests()


def test_default_is_per_io_budget(monkeypatch):
    monkeypatch.delenv(
        "RAPTOR_PROXY_UPSTREAM_HANDSHAKE_TIMEOUT_S", raising=False,
    )
    assert _upstream_handshake_timeout() == _PROXY_READ_TIMEOUT_S


def test_env_override(monkeypatch):
    monkeypatch.setenv("RAPTOR_PROXY_UPSTREAM_HANDSHAKE_TIMEOUT_S", "45")
    assert _upstream_handshake_timeout() == 45.0


@pytest.mark.parametrize("bad", ["", "abc", "0", "-3"])
def test_invalid_env_falls_back(monkeypatch, bad):
    monkeypatch.setenv("RAPTOR_PROXY_UPSTREAM_HANDSHAKE_TIMEOUT_S", bad)
    assert _upstream_handshake_timeout() == _PROXY_READ_TIMEOUT_S


def test_proxy_captures_value_at_construction(monkeypatch, reset_proxy):
    """The proxy is a long-lived singleton — the knob is read once at
    construction, matching how the upstream route itself is captured."""
    monkeypatch.setenv("RAPTOR_PROXY_UPSTREAM_HANDSHAKE_TIMEOUT_S", "45")
    proxy = proxy_mod.EgressProxy(allowed_hosts={"example.com"})
    try:
        assert proxy._upstream_handshake_timeout == 45.0
        # Later env mutation does not reconfigure the running proxy.
        monkeypatch.setenv(
            "RAPTOR_PROXY_UPSTREAM_HANDSHAKE_TIMEOUT_S", "99",
        )
        assert proxy._upstream_handshake_timeout == 45.0
    finally:
        proxy.stop()

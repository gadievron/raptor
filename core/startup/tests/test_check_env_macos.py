"""Tests for the macOS branch of core.startup.init.check_env().

Verifies that the startup banner correctly probes the seatbelt
backend on Darwin and produces an actionable warning when
sandbox-exec is unavailable. Cross-platform — patches sys.platform
so it runs on the Linux CI dev box too.
"""

from __future__ import annotations

import sys
from unittest import mock

import pytest

from core.startup import init as startup_init


@pytest.fixture
def reset_seatbelt_cache():
    """check_seatbelt_available() caches its result process-wide;
    tests here mock different return values so we must clear the
    cache to avoid one test's mock leaking into another."""
    from core.sandbox import state
    state._seatbelt_available_cache = None
    yield
    state._seatbelt_available_cache = None


def test_check_env_macos_seatbelt_available(reset_seatbelt_cache):
    """When seatbelt smoke test passes, the banner shows
    'sandbox ✓ (seatbelt)' and emits no sandbox warning."""
    with mock.patch.object(sys, "platform", "darwin"), \
         mock.patch("core.sandbox.check_seatbelt_available",
                     return_value=True):
        parts, warnings = startup_init.check_env(set())

    sandbox_parts = [p for p in parts if "sandbox" in p]
    assert sandbox_parts == ["sandbox ✓ (seatbelt)"]
    sandbox_warnings = [w for w in warnings if "sandbox" in w.lower()]
    assert sandbox_warnings == []


def test_check_env_macos_seatbelt_unavailable(reset_seatbelt_cache):
    """When seatbelt smoke test fails, the banner shows 'sandbox ✗'
    and emits a macOS-specific warning naming the diagnostic
    command operators can run."""
    with mock.patch.object(sys, "platform", "darwin"), \
         mock.patch("core.sandbox.check_seatbelt_available",
                     return_value=False):
        parts, warnings = startup_init.check_env(set())

    sandbox_parts = [p for p in parts if "sandbox" in p]
    assert sandbox_parts == ["sandbox ✗"]
    sandbox_warnings = [w for w in warnings if "sandbox" in w.lower()]
    assert any("sandbox-exec" in w for w in sandbox_warnings), (
        f"expected sandbox-exec diagnostic, got {sandbox_warnings!r}"
    )


def test_check_env_linux_unchanged(reset_seatbelt_cache):
    """Linux branch must remain its existing behaviour — never
    invoke check_seatbelt_available, only the Linux-layer probes.
    Regression catch for accidentally calling the macOS branch on
    Linux."""
    if sys.platform == "darwin":
        pytest.skip("Linux-only sanity check")
    with mock.patch("core.sandbox.check_seatbelt_available") as seatbelt_probe:
        startup_init.check_env(set())
    # Linux branch must NOT touch the seatbelt probe.
    assert not seatbelt_probe.called, (
        "Linux check_env unexpectedly called check_seatbelt_available"
    )

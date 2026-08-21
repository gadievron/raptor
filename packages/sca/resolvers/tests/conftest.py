"""Resolver-test fixtures.

``packages.sca.resolvers._check_tool`` caches per-process to avoid
re-invoking ``<tool> --version`` (which is ~1s per call for npm) on
every cascade attempt during a real scan. The tests monkeypatch
``subprocess.run`` per-test, so without resetting the cache between
tests, a tool's "available" verdict from one test leaks into the
next and breaks every downstream assertion.

This autouse fixture clears the cache before each resolver test.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _clear_check_tool_cache():
    from packages.sca.resolvers import _CHECK_TOOL_CACHE
    _CHECK_TOOL_CACHE.clear()
    yield
    _CHECK_TOOL_CACHE.clear()


@pytest.fixture(autouse=True)
def _accept_degraded_egress_tier(monkeypatch):
    """These tests exercise resolver/pipeline semantics, not sandbox
    tier posture. CI runners block unprivileged user namespaces
    (apparmor_restrict_unprivileged_userns=1), so the netns egress
    tier is unavailable there and the require_proxy_netns fail-closed
    guard (00015) would refuse every sandboxed call. Accept the
    degraded tier for the tests via the guard's own documented opt-in;
    the guard's behavior has its own dedicated tests in
    core/sandbox/tests/test_proxy_netns_enforcement.py.
    Subprocess-based e2e tests inherit it via os.environ."""
    monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")

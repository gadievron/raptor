"""Resolver-test fixtures.

``packages.sca.resolvers._check_tool`` caches per-process to avoid
re-invoking ``<tool> --version`` (which is ~1s per call for npm) on
every cascade attempt during a real scan. The tests monkeypatch
``subprocess.run`` per-test, so without resetting the cache between
tests, a tool's "available" verdict from one test leaks into the
next and breaks every downstream assertion.

This autouse fixture installs a private cache for each resolver test.
"""

from __future__ import annotations

import pytest
from pathlib import Path



@pytest.fixture(autouse=True)
def _clear_check_tool_cache(monkeypatch):
    from packages.sca import resolvers
    # Share the body's undo stack when it patches this same binding.
    monkeypatch.setattr(resolvers, "_CHECK_TOOL_CACHE", {})
    yield


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


@pytest.fixture(autouse=True)
def _owned_resolver_keepalive():
    """Own ticker resources and fail if a resolver owner forgets its pin."""
    import threading
    from core.run import scratch

    with pytest.MonkeyPatch.context() as owner_patch:
        stop = threading.Event()
        paths = set()
        owner_patch.setattr(scratch, "_keepalive_paths", paths)
        owner_patch.setattr(scratch, "_keepalive_thread", None)
        owner_patch.setattr(scratch, "_keepalive_loop", lambda: stop.wait())
        try:
            yield paths
        finally:
            stop.set()
            thread = scratch._keepalive_thread
            if thread is not None:
                thread.join(timeout=5)
                assert not thread.is_alive(), "owned resolver keepalive did not stop"
            leaked = [path for path in paths if Path(path).name.startswith("raptor-sca-")]
            assert not leaked, f"Resolver owner left workspace keepalives registered: {leaked}"

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

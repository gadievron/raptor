"""Shared fixtures for the wheel-compat test suite."""

from __future__ import annotations

from collections.abc import Callable, Iterator

import pytest

from packages.sca.wheel_compat.compat import clear_recommendation_cache


@pytest.fixture(autouse=True)
def _fresh_recommendation_cache() -> Iterator[Callable[[], None]]:
    """Clear the per-process recommendation cache around every test.

    Why per-test clearing is right HERE: the recommendation cache is
    keyed on ``(name, matrix-shape)`` and deliberately ignores the
    ``pypi_client`` argument. Tests in this suite hand a different
    stub client to every call, so two tests using the same package
    name and matrix shape share a cache entry — one test's cached
    result (including cached ``None`` negatives from a
    no-compatible-version stub) silently overrides the next test's
    stub. Clearing before AND after each test confines every stub's
    answers to its own test.

    Why production does NOT clear: within one real scan process every
    client answers from the same real PyPI, so entries never disagree
    — and the cache exists precisely so a dep pinned across multiple
    manifests pays the bounded release-history walk (with its
    per-version wheel-metadata inspection) only once per process.
    The process-lifetime cache stays; only the test boundary changes.

    Yields the boundary-clear callable so a test can reproduce the
    between-tests boundary inside itself (the stub-swap regression
    test in ``test_compat.py`` does exactly that).
    """
    clear_recommendation_cache()
    yield clear_recommendation_cache
    clear_recommendation_cache()

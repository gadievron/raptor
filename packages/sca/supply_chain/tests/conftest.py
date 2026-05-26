"""Per-test cleanup for the supply-chain test suite."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _reset_registry_metadata_meta_cache():
    """Clear the process-lifetime ``_Meta`` memo between tests.

    ``packages.sca.supply_chain.registry_metadata`` memoises parsed
    ``_Meta`` records keyed on ``(ecosystem, name)`` for the run
    lifetime — see commit-trail. Tests that swap fake registry
    clients for the same package name across cases would otherwise
    see the first case's parsed result on every subsequent call.
    """
    from packages.sca.supply_chain.registry_metadata import (
        _reset_meta_cache_for_tests,
    )
    _reset_meta_cache_for_tests()
    yield
    _reset_meta_cache_for_tests()

"""Per-test cleanup for the supply-chain test suite."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _reset_registry_metadata_meta_cache():
    """Own the parsed metadata memo under the production publication lock."""
    from packages.sca.supply_chain import registry_metadata
    from core.testing.module_state import isolated_module_state

    with isolated_module_state(registry_metadata, {"_META_CACHE": {}}, lock=registry_metadata._META_CACHE_LOCK):
        yield

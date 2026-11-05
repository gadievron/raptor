"""Per-test ownership of API counters shared by the metadata clients."""

import pytest


@pytest.fixture(autouse=True)
def _isolated_api_events(monkeypatch):
    from cve_diff.infra import api_status
    from core.testing.module_state import isolated_module_state

    with isolated_module_state(api_status, {
        "_events": type(api_status._events)(api_status._events.default_factory),
        "_cache_events": type(api_status._cache_events)(api_status._cache_events.default_factory),
    }, lock=api_status._lock):
        try:
            yield
        finally:
            monkeypatch.undo()

"""Own scratch ticker resources used by tool adapter tests."""

import pytest


@pytest.fixture(autouse=True)
def _owned_tool_scratch():
    from core.testing.scratch_state import isolated_scratch_keepalive

    with isolated_scratch_keepalive():
        yield

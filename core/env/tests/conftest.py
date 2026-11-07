"""Own scratch keepalives acquired by environment resource owners."""

import pytest

from core.testing.scratch_state import isolated_scratch_keepalive


@pytest.fixture(autouse=True)
def _owned_environment_scratch():
    with isolated_scratch_keepalive():
        yield

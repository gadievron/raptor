"""Own scratch state used by project artifact staging."""

import pytest

from core.testing.scratch_state import isolated_scratch_keepalive


@pytest.fixture(autouse=True)
def _owned_project_scratch():
    with isolated_scratch_keepalive():
        yield

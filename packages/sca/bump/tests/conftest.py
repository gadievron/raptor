"""Own the scratch ticker used by binary comparison tests."""

import pytest

from core.run import tmp_reaper
from core.testing.module_state import isolated_module_state
from core.testing.scratch_state import isolated_scratch_keepalive


@pytest.fixture(autouse=True)
def _owned_bump_scratch():
    with isolated_module_state(tmp_reaper, {
        "_RUNTIME_DIR_PREFIXES": set(tmp_reaper._RUNTIME_DIR_PREFIXES),
    }), isolated_scratch_keepalive():
        yield

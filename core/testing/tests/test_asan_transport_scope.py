"""The clean probe fixture owns its runner without dispatching native tools."""

from contextlib import nullcontext
import subprocess

import pytest

from core.testing import asan
from core.testing.tests import test_asan


@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_probe_runner_scope_preserves_borrowed_transport(failure):
    original_module = asan.subprocess
    original_run = subprocess.run
    original_cache = asan._runtime_unavailable_reason
    expected = pytest.raises(failure, match="owned body failure") if failure else nullcontext()
    with expected:
        with pytest.MonkeyPatch.context() as patch:
            fixture = test_asan.clear_probe_cache.__wrapped__(patch)
            next(fixture)
            try:
                test_asan.test_clean_runtime_probe_checks_execution_and_is_cached(patch, "healthy")
                assert subprocess.run is original_run
                assert asan.subprocess is not original_module
                assert asan.subprocess.run is not original_run
                assert asan.subprocess.TimeoutExpired is subprocess.TimeoutExpired
                assert asan._runtime_unavailable_reason is not original_cache
                if failure:
                    raise failure("owned body failure")
            finally:
                fixture.close()
    assert asan.subprocess is original_module
    assert subprocess.run is original_run
    assert asan._runtime_unavailable_reason is original_cache

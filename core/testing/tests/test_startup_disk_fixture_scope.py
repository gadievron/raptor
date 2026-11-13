"""Startup disk fixtures leave unrelated filesystem probes unchanged."""
from contextlib import nullcontext
import os
import sys

import pytest

from core.startup.tests import test_check_env_session as native


@pytest.mark.parametrize("method", [
    "test_abi_tier_shown_in_sandbox_part",
    "test_abi_below_4_warns_about_advisory_egress",
    "test_landlock_unavailable_no_abi_or_warning",
    "test_abi_probe_returning_zero_degrades_to_plain_feature",
])
@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_capability_fixture_restores_disk_probe(tmp_path, method, failure):
    namespace = native.startup_init.os
    statvfs = os.statvfs
    platform = sys.platform
    repo_root = native.startup_init.REPO_ROOT
    helper = native.patch_module_attribute
    entered, calls = [], []

    def checked(patch, module, binding, name, value):
        assert module is native.startup_init
        assert (binding, name) == ("os", "statvfs")

        def observed(path):
            calls.append(path)
            return value(path)

        private = helper(patch, module, binding, name, observed)
        entered.append(private)
        assert module.os is private
        assert os.statvfs is statvfs
        return private

    expected = pytest.raises(failure, match="owned body failure") if failure else nullcontext()
    with pytest.MonkeyPatch.context() as owner:
        repo = native.fake_repo.__wrapped__(tmp_path, owner)
        owner.setattr(native, "patch_module_attribute", checked)
        with expected:
            with pytest.MonkeyPatch.context() as body:
                getattr(native.TestSandboxCapabilityTier(), method)(repo, body)
                assert len(entered) == len(calls) == 1
                assert isinstance(os.statvfs(tmp_path), os.statvfs_result)
                assert len(calls) == 1
                if failure:
                    raise failure("owned body failure")
        assert native.startup_init.os is namespace
        assert os.statvfs is statvfs
        assert sys.platform is platform
    assert native.startup_init.REPO_ROOT is repo_root
    assert native.patch_module_attribute is helper

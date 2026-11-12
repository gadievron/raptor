"""Patch-apply route guards retain rejection without changing unrelated runners."""
from contextlib import nullcontext
import subprocess

import pytest

from packages.sca import patch_apply
from packages.sca.tests import test_patch_apply as native


@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_route_guard_owns_consumer_binding(tmp_path, failure):
    namespace, runner = patch_apply.subprocess, subprocess.run
    expected = pytest.raises(failure, match="owned body failure") if failure else nullcontext()
    with expected:
        with pytest.MonkeyPatch.context() as patch:
            native.test_apply_routes_through_run_untrusted(tmp_path, patch)
            assert subprocess.run is runner
            assert patch_apply.subprocess is not namespace
            assert patch_apply.subprocess.run is not runner
            assert patch_apply.subprocess.SubprocessError is namespace.SubprocessError
            if failure:
                raise failure("owned body failure")
    assert patch_apply.subprocess is namespace
    assert subprocess.run is runner


def test_actual_route_guard_still_rejects_unsandboxed_regression(tmp_path, monkeypatch):
    def unsafe_apply(target, patch_path):
        return patch_apply.subprocess.run(["git", "apply", str(patch_path)]).returncode

    monkeypatch.setattr(native, "apply_patch_to_target", unsafe_apply)
    with pytest.MonkeyPatch.context() as patch:
        with pytest.raises(AssertionError, match="must route through core.sandbox.context.run_untrusted"):
            native.test_apply_routes_through_run_untrusted(tmp_path, patch)

"""Joern failed-removal faults stay on their filesystem consumer."""
from contextlib import nullcontext
from pathlib import Path
import shutil

import pytest

from packages.joern.tests import test_permission_cleanup as native


@pytest.mark.parametrize("kind", ["slot", "build"])
@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_removal_fault_restores_consumer(tmp_path, caplog, kind, failure):
    namespace = native.atomic_fs.shutil
    remove = shutil.rmtree
    helper = native.patch_module_attribute
    expected_tree = tmp_path / (native.runner._CPG_SLOT_TARGET_PREFIX + "old"
                                if kind == "slot" else native.runner._CPG_BUILD_DIR_PREFIX + "old")
    faults = []
    entered = []

    def checked(patch, module, binding, name, value):
        assert module is native.atomic_fs
        assert (binding, name) == ("shutil", "rmtree")

        def observed(path, *args, **kwargs):
            assert Path(path) == expected_tree
            assert kwargs == {"ignore_errors": True}
            faults.append(path)
            return value(path, *args, **kwargs)

        private = helper(patch, module, binding, name, observed)
        entered.append(private)
        assert module.shutil is private
        assert shutil.rmtree is remove
        return private

    expected = pytest.raises(failure, match="owned body failure") if failure else nullcontext()
    with pytest.MonkeyPatch.context() as owner:
        owner.setattr(native, "patch_module_attribute", checked)
        with expected:
            with pytest.MonkeyPatch.context() as patch:
                native.test_failed_removal_does_not_log_success(tmp_path, patch, caplog, kind)
                assert len(entered) == 1
                assert faults == [str(expected_tree), str(expected_tree)]
                unrelated = tmp_path / "unrelated-cleanup"
                unrelated.mkdir()
                (unrelated / "payload").write_text("owned")
                shutil.rmtree(unrelated)
                assert not unrelated.exists()
                assert expected_tree.is_dir()
                if failure:
                    raise failure("owned body failure")
        assert native.atomic_fs.shutil is namespace
        assert shutil.rmtree is remove
    assert native.patch_module_attribute is helper

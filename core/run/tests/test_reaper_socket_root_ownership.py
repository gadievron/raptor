"""Short socket roots are owned before temporary-root setup can abort."""

import builtins
import shutil
import tempfile
from pathlib import Path
from types import FunctionType, SimpleNamespace

import pytest

from core.run.tests import test_tmp_reaper as native
from core.testing.module_state import isolated_module_state
from core.testing.tempdirs import private_tempfile_module


def _exercise(tmp_path, stage, error, after):
    roots = []
    failure = error("owned short-root setup error") if error else None
    private = private_tempfile_module(tempfile)

    def allocated(*args, **kwargs):
        root = tempfile.mkdtemp(*args, **kwargs)
        roots.append(Path(root))
        return root

    def importing(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "tempfile":
            return SimpleNamespace(mkdtemp=allocated)
        return builtins.__import__(name, globals, locals, fromlist, level)

    method = native.TestDirReaping.test_dir_with_answering_socket_kept_then_reaped
    body = FunctionType(method.__code__, {
        **method.__globals__,
        "__builtins__": {**vars(builtins), "__import__": importing},
    })
    try:
        with isolated_module_state(native._tempfile_owner, {"tempfile": private}):
            with pytest.MonkeyPatch.context() as patch:
                # Retain the native file's private-root and namespace setup.
                native._pin_sweep_roots.__wrapped__(patch)
                native._pin_root_pidns.__wrapped__(patch)
                native._idle_fixture_cwds.__wrapped__(patch)

                class Setup:
                    def setattr(self, *args, **kwargs):
                        if error and stage == "setattr" and not after:
                            raise failure
                        patch.setattr(*args, **kwargs)
                        if error and stage == "setattr":
                            raise failure

                    def delenv(self, *args, **kwargs):
                        if error and stage == "delenv" and not after:
                            raise failure
                        patch.delenv(*args, **kwargs)
                        if error and stage == "delenv":
                            raise failure

                if error:
                    with pytest.raises(error) as caught:
                        body(native.TestDirReaping(), Setup())
                    assert caught.value is failure
                else:
                    body(native.TestDirReaping(), Setup())
                assert len(roots) == 1
                assert not roots[0].exists()
    finally:
        for root in roots:
            shutil.rmtree(root, ignore_errors=True)


@pytest.mark.parametrize("stage", ["setattr", "delenv"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True])
def test_setup_errors_retire_short_root(tmp_path, stage, error, after):
    _exercise(tmp_path, stage, error, after)


def test_native_socket_keep_and_reap_retires_short_root(tmp_path):
    _exercise(tmp_path, "delenv", None, True)

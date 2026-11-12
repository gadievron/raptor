"""R2 wrapper fixture owns startup imports and the caller's mutable path."""
from contextlib import nullcontext
import builtins
import os
import runpy
import shutil
import sys

import pytest

from core.binary.tests import test_radare2_policy as native


@pytest.mark.parametrize("fresh", [True, False])
@pytest.mark.parametrize("outcome", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_r2_launch_fixture_restores_caller_state(tmp_path, fresh, outcome):
    lookup, importer = shutil.which, builtins.__import__
    path, path_values = sys.path, list(sys.path)
    argv, argv_values = sys.argv, list(sys.argv)
    wrapper_globals = native._WRAPPER_GLOBALS
    runner = runpy.run_path
    keys = ("_RAPTOR_TRUSTED", "OUTPUT_DIR", "R2_TARGET_DIR")
    env = {key: (key in os.environ, os.environ.get(key)) for key in keys}
    empty = tmp_path / "empty-path"
    empty.mkdir()
    assert shutil.which("r2", path=str(empty)) is None
    expected = pytest.raises(outcome, match="owned body failure") if outcome else nullcontext()
    with expected:
        with pytest.MonkeyPatch.context() as patch:
            launch = native.launch.__wrapped__(tmp_path, patch)
            native.test_full_policy_and_stdio_are_preserved(launch, patch, fresh)
            assert shutil.which is lookup
            assert shutil.which("r2", path=str(empty)) is None
            private_import = native._WRAPPER_GLOBALS["__builtins__"]["__import__"]
            private_shutil = private_import("shutil")
            assert private_shutil is not shutil
            assert private_shutil.which("r2", path=str(empty)) == str(launch[3])
            assert private_shutil.which("unrelated-missing-tool", path=str(empty)) is None
            assert builtins.__import__ is importer
            assert native.runpy.run_path is runner
            assert sys.path is not path
            assert path == path_values
            if outcome:
                raise outcome("owned body failure")
    assert shutil.which is lookup
    assert builtins.__import__ is importer
    assert runpy.run_path is runner
    assert native._WRAPPER_GLOBALS is wrapper_globals
    assert sys.path is path
    assert path == path_values
    assert sys.argv is argv
    assert argv == argv_values
    assert {key: (key in os.environ, os.environ.get(key)) for key in keys} == env

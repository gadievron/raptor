"""Native test directory entry is protected before its first mutation."""

import ast
import builtins
from contextlib import ExitStack
import inspect
import os
from pathlib import Path
import tempfile
from types import ModuleType, SimpleNamespace
import unittest

import pytest

from core.testing.module_views import module_function_view


ROOT = Path(__file__).resolve().parents[3]
CASES = (
    ("core/run/tests/test_output.py", "TestTargetMatchesProjectPredicate.test_relative_target_resolves_against_cwd"),
    ("packages/fuzzing/tests/test_agentic_fuzz_helpers.py", "TestCollectCrashFilesCwdSafety.test_empty_path_never_scans_cwd"),
    ("packages/fuzzing/tests/test_afl_runner.py", "TestCreateDefaultCorpus.test_corpus_anchored_to_output_dir_not_cwd"),
    ("core/project/tests/test_sessions.py", "RunLedgerTest.test_relative_finish_spelling_flips_the_record"),
    ("core/sandbox/tests/test_sandbox.py", "TestLandlockEnforcement.test_relative_output_path_does_not_break_landlock"),
)


def _method(path, scope, os_view, tmp_path):
    tree = ast.parse((ROOT / path).read_text())
    node = tree
    for part in scope.split("."):
        node = next(item for item in node.body if getattr(item, "name", None) == part)
    module = ModuleType("owned_native_directory_case")
    # Ledger production behaviour has its own unchanged native positive case.
    # Its unrelated start producer is a private no-op for this entry fault.
    module.__dict__.update(
        Path=Path, TemporaryDirectory=tempfile.TemporaryDirectory,
        tempfile=tempfile, os=os_view, __file__=str(ROOT / path),
        sessions=SimpleNamespace(ledger_record_start=lambda *args, **kwargs: None),
    )
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(ROOT / path), "exec"), vars(module))

    def importing(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "os" and level == 0:
            return os_view
        return builtins.__import__(name, globals, locals, fromlist, level)

    view = module_function_view(module, import_hook=importing)
    case = unittest.TestCase()
    run = tmp_path / "run"
    run.mkdir()
    case._mk_run = lambda name: run
    method = getattr(view, node.name)
    values = dict(self=case, tmp_path=tmp_path)
    return method, {key: values[key] for key in inspect.signature(method).parameters}


@pytest.mark.skipif(not hasattr(os, "fchdir"), reason="POSIX descriptor-backed directory safety net")
@pytest.mark.parametrize("path,scope", CASES, ids=[scope for _, scope in CASES])
@pytest.mark.parametrize("after_effect", [False, True])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
def test_native_directory_setup_rolls_back_before_retiring_temporary_paths(
    path, scope, after_effect, error, tmp_path,
):
    failure = error("directory setup interrupted")
    calls = []
    view = ModuleType("os")
    vars(view).update(vars(os))

    def changing(target):
        calls.append(target)
        if len(calls) == 1 and not after_effect:
            raise failure
        os.chdir(target)
        if len(calls) == 1:
            raise failure

    view.chdir = changing
    method, values = _method(path, scope, view, tmp_path)
    descriptor = os.open(".", os.O_RDONLY)
    with ExitStack() as safety:
        safety.callback(os.close, descriptor)
        safety.callback(os.fchdir, descriptor)
        before = os.fstat(descriptor)
        with pytest.raises(error) as caught:
            method(**values)
        after = os.stat(".")
    assert caught.value is failure
    assert len(calls) == 2, "entry and restoration must both be attempted"
    assert (after.st_dev, after.st_ino) == (before.st_dev, before.st_ino)

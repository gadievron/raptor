"""Separately compiled early setup component; native skip guard is untouched."""

import ast
import copy
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
import pytest

ROOT = Path(__file__).resolve().parents[3]
SETUP_PIN = "567131e330001b337a8f56e23df34f6af50a09dac006ce31329f29bf821a35b1"


def _exercise(tmp_path, refusal, expected_removed):
    source = ROOT / "packages/openant/tests/test_recovery_pinned_contract.py"
    text = source.read_text()
    tree = ast.parse(text)
    native_class = next(
        n
        for n in tree.body
        if isinstance(n, ast.ClassDef) and n.name == "TestRecoveryPinnedContract"
    )
    native = next(
        n
        for n in native_class.body
        if isinstance(n, ast.FunctionDef) and n.name == "setUpClass"
    )
    assert (
        hashlib.sha256(ast.get_source_segment(text, native).encode()).hexdigest()
        == SETUP_PIN
    )
    assert (
        len(native_class.decorator_list) == 1
    )  # Kept as source; never evaluated or copied.
    method = copy.deepcopy(native)
    stop = next(
        i
        for i, n in enumerate(method.body)
        if isinstance(n, ast.Expr)
        and isinstance(n.value, ast.Call)
        and ast.unparse(n.value.func) == "cls.scan_dir.mkdir"
    )
    method.body = method.body[: stop + 1]
    owners = []
    calls = []
    failure = OSError("owned recovery component mkdir refusal")

    class SetupBoundary(Exception):
        pass

    class OwnedPath(type(Path())):
        def mkdir(self, *args, **kwargs):
            assert len(owners) == 1 and self == Path(owners[0].name) / "scan"
            calls.append(str(self))
            if refusal:
                raise failure
            super().mkdir(*args, **kwargs)
            assert self.is_dir()
            raise SetupBoundary(
                "actual mkdir completed; later writes and integration not executed"
            )

    def temporary_directory(*args, **kwargs):
        assert not args and not kwargs
        owner = tempfile.TemporaryDirectory(dir=tmp_path)
        owners.append(owner)
        return owner

    def forbidden(self):
        raise AssertionError("test body reached after failed setup component")

    namespace = {
        "tempfile": SimpleNamespace(TemporaryDirectory=temporary_directory),
        "Path": OwnedPath,
    }
    exec(
        compile(ast.Module(body=[method], type_ignores=[]), str(source), "exec"),
        namespace,
    )
    case = type(
        "RecoverySetupComponent",
        (unittest.TestCase,),
        {
            "setUpClass": namespace["setUpClass"],
            "test_boundary": forbidden,
            "__module__": __name__,
        },
    )

    class Result(unittest.TestResult):
        def addError(self, test, err):
            self.actual_error = err[1]
            super().addError(test, err)

    result = Result()
    try:
        unittest.TestSuite([case("test_boundary")]).run(result)
        assert result.testsRun == 0 and len(result.errors) == 1 and not result.failures
        assert len(owners) == 1 and len(calls) == 1
        assert (
            "owned recovery component mkdir refusal"
            if refusal
            else "actual mkdir completed"
        ) in result.errors[0][1]
        assert (
            (result.actual_error is failure)
            if refusal
            else isinstance(result.actual_error, SetupBoundary)
        )
        assert case._classSetupFailed and not case._class_cleanups
        root = Path(owners[0].name)
        assert (not root.exists()) is expected_removed
        if not expected_removed:
            assert root.is_dir()
        (tmp_path / "observation.json").write_text(
            json.dumps(
                {
                    "refusal": refusal,
                    "directory_removed_before_rescue": expected_removed,
                    "real_unittest_class_setup_error": True,
                    "test_bodies_run": result.testsRun,
                    "scope": "synthetic pinned early setup component only; native guard unevaluated and unchanged; no class admission, external checkout or integration execution",
                }
            )
            + "\n"
        )
    finally:
        case.doClassCleanups()
        for owner in owners:
            owner.cleanup()


@pytest.mark.parametrize(
    "refusal", [False, True], ids=["mkdir-boundary", "mkdir-error"]
)
def test_recovery_setup_component_ownership(tmp_path, refusal):
    _exercise(tmp_path, refusal, True)

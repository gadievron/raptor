"""Exact argv binding lifecycle component; relay CLI remains unexecuted."""

import ast
import copy
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

import pytest

ROOT = Path(__file__).resolve().parents[3]
PINS = {
    "setUp": "5759e71b8f7f2343c630ccd1fb849f544c7dec97b1669149833dadd64b7d161e",
    "tearDown": "9ca5577de5212b2fd733c2aa360392d6d6a7462683bc3fd4a4b6cf3fea777de8",
    "_drive": "5a239c15e771df8da257291db06764a0cdd6df5e8cfa150575238993bd08b917",
}


def _exercise(tmp_path, body_error, expected_identity):
    source = ROOT / "packages/autonomous/tests/test_relay_handler_scoping.py"
    text = source.read_text()
    tree = ast.parse(text)
    cls = next(
        n
        for n in tree.body
        if isinstance(n, ast.ClassDef) and n.name == "RelayHandlerLiveTests"
    )
    methods = {
        n.name: n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name in PINS
    }
    assert len(methods) == 3
    for name, node in methods.items():
        assert (
            hashlib.sha256(ast.get_source_segment(text, node).encode()).hexdigest()
            == PINS[name]
        )
    assert len(cls.decorator_list) == 1  # Kept as source, not copied or evaluated.
    setup = copy.deepcopy(methods["setUp"])
    setup.body = setup.body[:3]
    assert all(isinstance(n, (ast.Assign, ast.AnnAssign)) for n in setup.body)
    assert [
        ast.unparse(n.targets[0] if isinstance(n, ast.Assign) else n.target)
        for n in setup.body
    ] == ["self._env", "self._argv", "self._patched"]
    drive = [
        n
        for n in methods["_drive"].body
        if isinstance(n, ast.Assign) and ast.unparse(n.targets[0]) == "sys.argv"
    ]
    assert len(drive) == 1
    env = {"OWNED_RELAY_COMPONENT": "retained"}
    namespace = {
        "sys": sys,
        "os": SimpleNamespace(environ=env),
        "argv": ["--owned-fixture"],
    }
    exec(
        compile(
            ast.Module(body=[setup, methods["tearDown"]], type_ignores=[]),
            str(source),
            "exec",
        ),
        namespace,
    )
    original = sys.argv
    values = list(original)
    primary = RuntimeError("controlled relay fixture body boundary")

    def body(self):
        exec(
            compile(ast.Module(body=drive, type_ignores=[]), str(source), "exec"),
            namespace,
        )
        assert sys.argv == ["raptor_agentic.py", "--owned-fixture"]
        assert sys.argv is not original and original == values
        if body_error:
            raise primary

    class Result(unittest.TestResult):
        actual_error = None

        def addError(self, test, err):
            self.actual_error = err[1]
            super().addError(test, err)

    case = type(
        "RelayArgvComponent",
        (unittest.TestCase,),
        {
            "setUp": namespace["setUp"],
            "tearDown": namespace["tearDown"],
            "test_boundary": body,
            "__module__": __name__,
        },
    )
    result = Result()
    try:
        unittest.TestSuite([case("test_boundary")]).run(result)
        assert (
            result.testsRun == 1
            and not result.failures
            and len(result.errors) == int(body_error)
        )
        assert (
            (result.actual_error is primary)
            if body_error
            else result.actual_error is None
        )
        assert sys.argv == values and original == values
        assert (sys.argv is original) is expected_identity
        (tmp_path / "observation.json").write_text(
            json.dumps(
                {
                    "body_error": body_error,
                    "argv_identity_preserved_before_rescue": expected_identity,
                    "argv_values_preserved": True,
                    "scope": "exact argv lifecycle component only, actual sys binding/real unittest cleanup; private environment mapping, no native class admission, CLI/Git/provider/environment-restoration/integration proof",
                }
            )
            + "\n"
        )
    finally:
        sys.argv = original
        assert original == values


@pytest.mark.parametrize(
    "body_error", [False, True], ids=["complete", "controlled-body-error"]
)
def test_relay_argv_fixture_ownership(tmp_path, body_error):
    _exercise(tmp_path, body_error, True)

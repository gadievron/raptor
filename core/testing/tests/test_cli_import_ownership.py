"""CLI import helpers restore the caller before tests or collection continue."""
from functools import lru_cache
import ast
import importlib.machinery
import importlib.util
import os
from pathlib import Path
import sys
import types
from typing import Any
from unittest.mock import patch

import pytest

_REPO = Path(__file__).resolve().parents[3]
_OWNERS = [('core/audit/tests/test_review_cli_toolruns.py', '_load_cli'), ('core/audit/tests/test_guess_target_corroboration.py', '_load_raptor_audit'), ('core/coverage/tests/test_review_cli_project_dir.py', '_load_cli'), ('core/coverage/tests/test_review_cli_layers.py', '_load_cli'), ('core/run/tests/test_validation_helper_stage_guards.py', '_load_helper'), ('core/run/tests/test_validation_helper_poc_build.py', '_load_helper'), ('core/run/tests/test_validation_helper_include_facts.py', '_load_helper'), ('core/run/tests/test_validation_helper_gadget_facts.py', '_load_helper'), ('core/run/tests/test_validation_helper_findings_import.py', '_load_helper'), ('core/run/tests/test_sca_run_lifecycle.py', '_load_script'), ('core/run/tests/test_lifecycle_cost_gate.py', '_load_script'), ('core/sandbox/tests/test_seatbelt_shim.py', 'test_no_path_relative_ps'), ('packages/exploitability_validation/tests/test_findings_import_field_mapping.py', 'helper_module')]


@lru_cache(maxsize=None)
def _loader_code(file, name):
    tree = ast.parse((_REPO / file).read_text())
    function = next(node for node in ast.walk(tree)
                    if isinstance(node, ast.FunctionDef) and node.name == name)
    function.decorator_list = []
    return compile(ast.Module(body=[function], type_ignores=[]), file, "exec")


def _loader(file, name, root):
    namespace = dict(__file__=str(_REPO / file), __name__="owned_cli_import",
                     os=os, sys=sys, types=types, pytest=pytest, patch=patch,
                     Path=Path, Any=Any, importlib=importlib,
                     SourceFileLoader=importlib.machinery.SourceFileLoader,
                     ModuleType=types.ModuleType, REPO_ROOT=root,
                     _AUDIT_PATH=root / "libexec/raptor-audit",
                     SHIM_PATH=root / "libexec/raptor-seatbelt-shim",
                     HELPER_PATH=root / "libexec/raptor-validation-helper")
    exec(_loader_code(file, name), namespace)
    return namespace[name]


def _set_caller(monkeypatch, marker):
    if marker is None:
        monkeypatch.delenv("_RAPTOR_TRUSTED", raising=False)
    else:
        monkeypatch.setenv("_RAPTOR_TRUSTED", marker)
    monkeypatch.setattr(sys, "path", [*sys.path, "/owned/duplicate", "/owned/duplicate"])
    return dict(os.environ), sys.path, list(sys.path)


def _assert_caller(before):
    environment, path, values = before
    assert dict(os.environ) == environment
    assert sys.path is path
    assert sys.path == values


@pytest.mark.parametrize("file,name", _OWNERS, ids=[Path(p).stem for p, _ in _OWNERS])
@pytest.mark.parametrize("marker", [None, "", "caller"], ids=["missing", "empty", "borrowed"])
@pytest.mark.parametrize("outcome", ["normal", "error", "interrupt"])
def test_cli_loader_restores_after_real_execution(tmp_path, monkeypatch, file, name, marker, outcome):
    libexec = tmp_path / "libexec"
    libexec.mkdir()
    source = ("import os, sys\n"
              "assert os.environ['_RAPTOR_TRUSTED'] == '1'\n"
              "sys.path.append('/owned/import-side-effect')\n"
              "_PS_CANDIDATES = ('/owned/ps',)\n")
    if outcome != "normal":
        source += ("raise RuntimeError('owned import failed')\n" if outcome == "error"
                   else "raise KeyboardInterrupt('owned import interrupted')\n")
    for script in ("raptor-audit", "raptor-review", "raptor-validation-helper",
                   "raptor-run-lifecycle", "raptor-sca-run", "raptor-seatbelt-shim"):
        (libexec / script).write_text(source)
    load = _loader(file, name, tmp_path)
    before = _set_caller(monkeypatch, marker)
    caught = None
    try:
        result = load(None) if name.startswith("test_") else load()
    except BaseException as error:
        caught = error
    _assert_caller(before)
    if outcome == "normal":
        assert caught is None, repr(caught)
        assert result is None if name.startswith("test_") else isinstance(result, types.ModuleType)
    else:
        expected = RuntimeError if outcome == "error" else KeyboardInterrupt
        assert isinstance(caught, expected), repr(caught)
        assert "owned import" in str(caught)


@pytest.mark.parametrize("file,name", _OWNERS, ids=[Path(p).stem for p, _ in _OWNERS])
@pytest.mark.parametrize("marker", [None, "", "caller"], ids=["missing", "empty", "borrowed"])
def test_real_cli_import_preserves_borrowed_marker(monkeypatch, file, name, marker):
    load = _loader(file, name, _REPO)
    before = _set_caller(monkeypatch, marker)
    result = load(None) if name.startswith("test_") else load()
    _assert_caller(before)
    assert result is None if name.startswith("test_") else isinstance(result, types.ModuleType)


@pytest.mark.parametrize("file", [
    "core/audit/tests/test_review_cli_toolruns.py",
    "core/audit/tests/test_guess_target_corroboration.py",
    "core/coverage/tests/test_review_cli_project_dir.py",
    "core/coverage/tests/test_review_cli_layers.py",
], ids=lambda file: Path(file).stem)
@pytest.mark.parametrize("marker", [None, "", "caller"], ids=["missing", "empty", "borrowed"])
def test_collection_time_cli_import_restores_caller(monkeypatch, file, marker):
    path = _REPO / file
    loader = importlib.machinery.SourceFileLoader("owned_collection_import", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    before = _set_caller(monkeypatch, marker)
    loader.exec_module(module)
    _assert_caller(before)
    assert isinstance(getattr(module, "_cli", getattr(module, "audit_cli", None)), types.ModuleType)


@pytest.mark.parametrize("file,name", [owner for owner in _OWNERS if "review_cli" in owner[0]],
                         ids=lambda value: Path(value).stem)
@pytest.mark.parametrize("key", ["PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME", "PYTHONUSERBASE"])
@pytest.mark.parametrize("value", [None, "", "/owned/interpreter-override"],
                         ids=["missing", "empty", "borrowed"])
@pytest.mark.parametrize("outcome", ["normal", "error", "interrupt"])
def test_review_import_owns_interpreter_environment(tmp_path, monkeypatch, file, name, key, value, outcome):
    libexec = tmp_path / "libexec"
    libexec.mkdir()
    source = ("import os, sys\n"
              "assert not any(os.environ.get(key) for key in "
              "('PYTHONPATH', 'PYTHONSTARTUP', 'PYTHONHOME', 'PYTHONUSERBASE'))\n"
              "sys.path.append('/owned/import-side-effect')\n")
    if outcome != "normal":
        source += ("raise RuntimeError('owned import failed')\n" if outcome == "error"
                   else "raise KeyboardInterrupt('owned import interrupted')\n")
    (libexec / "raptor-review").write_text(source)
    if value is None:
        monkeypatch.delenv(key, raising=False)
    else:
        monkeypatch.setenv(key, value)
    before = _set_caller(monkeypatch, "caller")
    load = _loader(file, name, tmp_path)
    caught = None
    try:
        load()
    except BaseException as error:
        caught = error
    _assert_caller(before)
    expected = {"error": RuntimeError, "interrupt": KeyboardInterrupt}.get(outcome)
    assert caught is None if expected is None else isinstance(caught, expected), repr(caught)

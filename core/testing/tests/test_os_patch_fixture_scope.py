"""Exercise native os-patch fixtures without running their I/O bodies."""
import ast
from core.testing.mock_sources import as_patch_call
import copy
from functools import lru_cache
import importlib
from pathlib import Path
import sys
import os
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest

from core.testing.module_bindings import patch_module_attribute

_REPO = Path(__file__).resolve().parents[3]
_SPECS = [('core/json/tests/test_utils.py', 'core.json.utils'),
 ('core/project/tests/test_oplock.py', 'core.project.oplock'),
 ('core/sage/tests/test_rowmac_key_guard.py', 'core.sage.rowmac'),
 ('packages/codeql/tests/test_database_manager.py', 'packages.codeql.database_manager'),
 ('packages/sca/tests/test_atomic.py', 'core.atomic_fs'),
 ('core/json/tests/test_utils.py', 'core.source.gated'),
 ('core/sage/tests/test_rowmac_key_guard.py', 'core.security.mac_key')]


@lru_cache(maxsize=None)
def _tree(file):
    return ast.parse((_REPO / file).read_text())


def _patches(file):
    calls = []
    for node in ast.walk(_tree(file)):
        node = as_patch_call(node)
        if not isinstance(node, ast.Call) or not node.args:
            continue
        name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
        target = node.args[0]
        if name == "patch" and isinstance(target, ast.Constant) and isinstance(target.value, str) and ".os." in target.value and target.value.rsplit(".os.", 1)[1] in {"sched_getaffinity", "cpu_count", "sysconf", "fstat", "stat", "rename", "replace", "fsync"}:
            calls.append(node)
    return sorted(calls, key=lambda node: node.lineno)


def _cases():
    return [pytest.param(file, module, index, node.args[0].value,
                         id=Path(file).stem + "-" + module.rsplit(".", 1)[1] + "-" + str(index))
            for file, module in _SPECS
            for index, node in enumerate(_patches(file))]


@lru_cache(maxsize=None)
def _fixture(file):
    node = next((node for node in _tree(file).body if isinstance(node, ast.FunctionDef) and node.name == "_isolate_os_patch_targets"), None)
    if node is None:
        # The original-code baseline has no owning fixture.
        return lambda monkeypatch: None
    node = copy.deepcopy(node)
    node.decorator_list = []
    code = compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])), file, "exec")
    namespace = {"patch_module_attribute": patch_module_attribute}
    exec(code, namespace)
    return namespace[node.name]


@lru_cache(maxsize=None)
def _module(name):
    with patch.object(sys, "path", sys.path.copy()):
        return importlib.import_module(name)


def _assert_namespace(owner, before):
    changed = [name for name, value in before.items() if vars(owner).get(name) is not value]
    added = sorted(set(vars(owner)) - set(before))
    assert changed == [] and added == [], (changed, added)


@pytest.mark.parametrize("file,module,index,target", _cases())
@pytest.mark.parametrize("borrowed", [False, True], ids=["ordinary", "borrowed"])
@pytest.mark.parametrize("exit_mode", ["normal", "error", "interrupt"])
def test_native_fixture_owns_string_os_patch(file, module, index, target, borrowed, exit_mode):
    consumer = _module(module)
    assert isinstance(consumer, ModuleType)
    with pytest.MonkeyPatch.context() as inherited_scope:
        if borrowed:
            view = ModuleType(consumer.os.__name__)
            vars(view).update(vars(consumer.os))
            inherited_scope.setitem(vars(consumer), "os", view)
            assert consumer.os is view
        original = consumer.os
        raw = dict(vars(consumer))
        inherited = dict(vars(original))
        shared = dict(vars(os))
        name = target.rsplit(".", 1)[1]
        fake_os = MagicMock(name="owned_os")
        caught = None
        try:
            with pytest.MonkeyPatch.context() as scope:
                _fixture(file)(scope)
                # Resolve the actual native string target against the real
                # production module. No native test body or worker is started.
                allow_create = any(keyword.arg == "create" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True for keyword in _patches(file)[index].keywords)
                with patch(target, new=fake_os, create=allow_create):
                    _assert_namespace(os, shared)
                    _assert_namespace(original, inherited)
                    lookup = getattr(consumer.os, name)
                    if module == target.rsplit(".os.", 1)[0]:
                        assert lookup is fake_os
                    else:
                        assert consumer.os is not original
                        assert lookup is not getattr(original, name)
                        assert lookup("owned-discovery-probe") is fake_os.return_value
                    if exit_mode != "normal":
                        raise RuntimeError("owned scope exit") if exit_mode == "error" else KeyboardInterrupt("owned scope exit")
        except BaseException as error:
            caught = error
        assert consumer.os is original
        _assert_namespace(consumer, raw)
        _assert_namespace(original, inherited)
        _assert_namespace(os, shared)
        if exit_mode == "normal":
            assert caught is None, repr(caught)
        else:
            assert isinstance(caught, RuntimeError if exit_mode == "error" else KeyboardInterrupt), repr(caught)
            assert str(caught) == "owned scope exit"


@pytest.mark.parametrize("borrowed", [False, True])
def test_unmodified_os_control(borrowed):
    file, module = _SPECS[0]
    consumer = _module(module)
    with pytest.MonkeyPatch.context() as inherited_scope:
        if borrowed:
            view = ModuleType(consumer.os.__name__)
            vars(view).update(vars(consumer.os))
            inherited_scope.setitem(vars(consumer), "os", view)
            assert consumer.os is view
        original = consumer.os
        before = dict(vars(original))
        with pytest.MonkeyPatch.context() as scope:
            _fixture(file)(scope)
            assert consumer.os.getpid is original.getpid
            _assert_namespace(original, before)
        assert consumer.os is original
        _assert_namespace(original, before)

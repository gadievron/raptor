"""Exercise native clock-patch fixtures without running their I/O bodies."""
import ast
import copy
from functools import lru_cache
import importlib
from pathlib import Path
import sys
import time
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest

from core.testing.module_bindings import patch_module_attribute

_REPO = Path(__file__).resolve().parents[3]
_SPECS = [('core/env/tests/test_provision.py', 'core.container.containers'),
 ('core/http/tests/test_urllib_backend.py', 'core.http.urllib_backend'),
 ('core/llm/tests/test_resource_governor.py', 'core.llm.client'),
 ('core/sage/tests/test_rowmac.py', 'core.security.mac_key'),
 ('core/sage/tests/test_sage_hooks.py', 'core.sage.hooks'),
 ('packages/cve_env/tests/unit/test_bench_replay_verify.py', 'cve_env.tools.verify'),
 ('packages/cve_env/tests/unit/test_docker_run.py', 'core.container.containers'),
 ('packages/cve_env/tests/unit/test_image_resolve_arch.py',
  'cve_env.tools.image_resolve'),
 ('packages/cve_env/tests/unit/test_verify.py', 'cve_env.tools.verify'),
 ('packages/joern/tests/test_relaunch_on_death.py', 'packages.joern.server'),
 ('packages/web/tests/test_oob_expectations.py', 'packages.web.oob')]


@lru_cache(maxsize=None)
def _tree(file):
    return ast.parse((_REPO / file).read_text())


def _patches(file):
    calls = []
    for node in ast.walk(_tree(file)):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
        target = node.args[0]
        if name == "patch" and isinstance(target, ast.Constant) and isinstance(target.value, str) and ".time." in target.value:
            calls.append(node)
    return sorted(calls, key=lambda node: node.lineno)


def _cases():
    return [pytest.param(file, module, index, node.args[0].value,
                         id=Path(file).stem + "-" + str(index))
            for file, module in _SPECS
            for index, node in enumerate(_patches(file))]


@lru_cache(maxsize=None)
def _fixture(file):
    node = next((node for node in _tree(file).body if isinstance(node, ast.FunctionDef) and node.name == "_isolate_clock_patch_targets"), None)
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
def test_native_fixture_owns_string_clock_patch(file, module, index, target, borrowed, exit_mode):
    consumer = _module(module)
    assert isinstance(consumer, ModuleType)
    with pytest.MonkeyPatch.context() as inherited_scope:
        if borrowed:
            view = ModuleType(consumer.time.__name__)
            vars(view).update(vars(consumer.time))
            inherited_scope.setitem(vars(consumer), "time", view)
        original = consumer.time
        raw = dict(vars(consumer))
        inherited = dict(vars(original))
        shared = dict(vars(time))
        name = target.rsplit(".", 1)[1]
        fake_clock = MagicMock(name="owned_clock")
        caught = None
        try:
            with pytest.MonkeyPatch.context() as scope:
                _fixture(file)(scope)
                # Resolve the actual native string target against the real
                # production module. No native test body or worker is started.
                with patch(target, new=fake_clock):
                    _assert_namespace(time, shared)
                    _assert_namespace(original, inherited)
                    assert getattr(consumer.time, name) is fake_clock
                    if exit_mode != "normal":
                        raise RuntimeError("owned scope exit") if exit_mode == "error" else KeyboardInterrupt("owned scope exit")
        except BaseException as error:
            caught = error
        assert consumer.time is original
        _assert_namespace(consumer, raw)
        _assert_namespace(original, inherited)
        _assert_namespace(time, shared)
        if exit_mode == "normal":
            assert caught is None, repr(caught)
        else:
            assert isinstance(caught, RuntimeError if exit_mode == "error" else KeyboardInterrupt), repr(caught)
            assert str(caught) == "owned scope exit"


@pytest.mark.parametrize("borrowed", [False, True])
def test_unmodified_clock_control(borrowed):
    file, module = _SPECS[0]
    consumer = _module(module)
    with pytest.MonkeyPatch.context() as inherited_scope:
        if borrowed:
            view = ModuleType(consumer.time.__name__)
            vars(view).update(vars(consumer.time))
            inherited_scope.setitem(vars(consumer), "time", view)
        original = consumer.time
        before = dict(vars(original))
        with pytest.MonkeyPatch.context() as scope:
            _fixture(file)(scope)
            assert consumer.time.sleep is original.sleep
            _assert_namespace(original, before)
        assert consumer.time is original
        _assert_namespace(original, before)

"""Exercise native runner-patch fixtures without running their I/O bodies."""
import ast
from core.testing.mock_sources import as_patch_call
import copy
from functools import lru_cache
import importlib
from pathlib import Path
import sys
import subprocess
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest

from core.testing.module_bindings import patch_module_attribute

_REPO = Path(__file__).resolve().parents[3]
_SPECS = [('core/audit/tests/test_validate.py', 'core.orchestration.skill_dispatch'),
 ('core/orchestration/tests/test_skill_dispatch_checklist_timeout.py',
  'core.orchestration.skill_dispatch'),
 ('core/orchestration/tests/test_skill_dispatch.py', 'core.orchestration.skill_dispatch'),
 ('core/orchestration/tests/test_lifecycle_trust_marker.py', 'core.orchestration.skill_dispatch'),
 ('core/orchestration/tests/test_agentic_passes_integration.py',
  'core.orchestration.skill_dispatch'),
 ('core/orchestration/tests/test_agentic_passes.py', 'core.orchestration.skill_dispatch'),
 ('packages/fuzzing/tests/test_cargofuzz_runner.py', 'packages.fuzzing.cargofuzz_runner'),
 ('packages/fuzzing/tests/test_capability.py', 'packages.fuzzing.capability')]


@lru_cache(maxsize=None)
def _tree(file):
    return ast.parse((_REPO / file).read_text())


def _patches(file, module):
    calls = []
    for node in ast.walk(_tree(file)):
        node = as_patch_call(node)
        if not isinstance(node, ast.Call) or not node.args:
            continue
        name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
        target = node.args[0]
        if name == "patch" and isinstance(target, ast.Constant) and isinstance(target.value, str) and target.value == module + ".subprocess.run":
            calls.append(node)
    return sorted(calls, key=lambda node: node.lineno)


def _cases():
    return [pytest.param(file, module, index, node.args[0].value,
                         id=Path(file).stem + "-" + str(index))
            for file, module in _SPECS
            for index, node in enumerate(_patches(file, module))]


@lru_cache(maxsize=None)
def _fixture(file):
    node = next((node for node in _tree(file).body if isinstance(node, ast.FunctionDef) and node.name == "_isolate_subprocess_run_patches"), None)
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
def test_native_fixture_owns_string_runner_patch(file, module, index, target, borrowed, exit_mode):
    consumer = _module(module)
    assert isinstance(consumer, ModuleType)
    with pytest.MonkeyPatch.context() as inherited_scope:
        if borrowed:
            view = ModuleType(consumer.subprocess.__name__)
            vars(view).update(vars(consumer.subprocess))
            inherited_scope.setitem(vars(consumer), "subprocess", view)
        original = consumer.subprocess
        raw = dict(vars(consumer))
        inherited = dict(vars(original))
        shared = dict(vars(subprocess))
        name = target.rsplit(".", 1)[1]
        fake_runner = MagicMock(name="owned_runner")
        caught = None
        try:
            with pytest.MonkeyPatch.context() as scope:
                _fixture(file)(scope)
                # Resolve the actual native string target against the real
                # production module. No native test body or worker is started.
                with patch(target, new=fake_runner):
                    _assert_namespace(subprocess, shared)
                    _assert_namespace(original, inherited)
                    assert getattr(consumer.subprocess, name) is fake_runner
                    if exit_mode != "normal":
                        raise RuntimeError("owned scope exit") if exit_mode == "error" else KeyboardInterrupt("owned scope exit")
        except BaseException as error:
            caught = error
        assert consumer.subprocess is original
        _assert_namespace(consumer, raw)
        _assert_namespace(original, inherited)
        _assert_namespace(subprocess, shared)
        if exit_mode == "normal":
            assert caught is None, repr(caught)
        else:
            assert isinstance(caught, RuntimeError if exit_mode == "error" else KeyboardInterrupt), repr(caught)
            assert str(caught) == "owned scope exit"


@pytest.mark.parametrize("borrowed", [False, True])
def test_unmodified_runner_control(borrowed):
    file, module = _SPECS[0]
    consumer = _module(module)
    with pytest.MonkeyPatch.context() as inherited_scope:
        if borrowed:
            view = ModuleType(consumer.subprocess.__name__)
            vars(view).update(vars(consumer.subprocess))
            inherited_scope.setitem(vars(consumer), "subprocess", view)
        original = consumer.subprocess
        before = dict(vars(original))
        with pytest.MonkeyPatch.context() as scope:
            _fixture(file)(scope)
            assert consumer.subprocess.run is original.run
            _assert_namespace(original, before)
        assert consumer.subprocess is original
        _assert_namespace(original, before)

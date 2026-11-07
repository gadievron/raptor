"""Exercise native shutil-patch fixtures without running their I/O bodies."""
import ast
from core.testing.mock_sources import as_patch_call
import copy
from functools import lru_cache
import importlib
from pathlib import Path
import sys
import shutil
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest

from core.testing.module_bindings import patch_module_attribute

_REPO = Path(__file__).resolve().parents[3]
_SPECS = [('core/llm/tests/test_bedrock_detection.py', 'core.llm.detection'),
 ('core/startup/tests/test_check_tools.py', 'core.startup.init'),
 ('packages/codeql/tests/test_database_manager.py', 'packages.codeql.database_manager'),
 ('packages/cve_env/tests/unit/test_migration_resilience.py', 'core.container.compose'),
 ('packages/exploit_feasibility/tests/test_mitigation_facts.py', 'packages.exploit_feasibility.api'),
 ('packages/fuzzing/tests/test_capability.py', 'packages.fuzzing.capability'),
 ('packages/fuzzing/tests/test_cargofuzz_orchestration.py', 'packages.fuzzing.target_detector'),
 ('packages/fuzzing/tests/test_cargofuzz_runner.py', 'packages.fuzzing.cargofuzz_runner'),
 ('packages/fuzzing/tests/test_jazzer_orchestration.py', 'packages.fuzzing.target_detector'),
 ('packages/fuzzing/tests/test_target_detector.py', 'packages.fuzzing.target_detector'),
 ('packages/fuzzing/tests/test_capability.py', 'packages.binary_analysis.radare2_understand')]


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
        if name == "patch" and isinstance(target, ast.Constant) and isinstance(target.value, str) and ".shutil." in target.value:
            calls.append(node)
    return sorted(calls, key=lambda node: node.lineno)


def _cases():
    return [pytest.param(file, module, index, node.args[0].value,
                         id=Path(file).stem + "-" + module.rsplit(".", 1)[1] + "-" + str(index))
            for file, module in _SPECS
            for index, node in enumerate(_patches(file))]


@lru_cache(maxsize=None)
def _fixture(file):
    node = next((node for node in _tree(file).body if isinstance(node, ast.FunctionDef) and node.name == "_isolate_shutil_patch_targets"), None)
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
def test_native_fixture_owns_string_shutil_patch(file, module, index, target, borrowed, exit_mode):
    consumer = _module(module)
    assert isinstance(consumer, ModuleType)
    with pytest.MonkeyPatch.context() as inherited_scope:
        if borrowed:
            view = ModuleType(consumer.shutil.__name__)
            vars(view).update(vars(consumer.shutil))
            inherited_scope.setitem(vars(consumer), "shutil", view)
            assert consumer.shutil is view
        original = consumer.shutil
        raw = dict(vars(consumer))
        inherited = dict(vars(original))
        shared = dict(vars(shutil))
        name = target.rsplit(".", 1)[1]
        fake_shutil = MagicMock(name="owned_shutil")
        caught = None
        try:
            with pytest.MonkeyPatch.context() as scope:
                _fixture(file)(scope)
                # Resolve the actual native string target against the real
                # production module. No native test body or worker is started.
                with patch(target, new=fake_shutil):
                    _assert_namespace(shutil, shared)
                    _assert_namespace(original, inherited)
                    lookup = getattr(consumer.shutil, name)
                    if module == target.rsplit(".shutil.", 1)[0]:
                        assert lookup is fake_shutil
                    else:
                        assert consumer.shutil is not original
                        assert lookup is not getattr(original, name)
                        assert lookup("owned-discovery-probe") is fake_shutil.return_value
                    if exit_mode != "normal":
                        raise RuntimeError("owned scope exit") if exit_mode == "error" else KeyboardInterrupt("owned scope exit")
        except BaseException as error:
            caught = error
        assert consumer.shutil is original
        _assert_namespace(consumer, raw)
        _assert_namespace(original, inherited)
        _assert_namespace(shutil, shared)
        if exit_mode == "normal":
            assert caught is None, repr(caught)
        else:
            assert isinstance(caught, RuntimeError if exit_mode == "error" else KeyboardInterrupt), repr(caught)
            assert str(caught) == "owned scope exit"


@pytest.mark.parametrize("borrowed", [False, True])
def test_unmodified_shutil_control(borrowed):
    file, module = _SPECS[0]
    consumer = _module(module)
    with pytest.MonkeyPatch.context() as inherited_scope:
        if borrowed:
            view = ModuleType(consumer.shutil.__name__)
            vars(view).update(vars(consumer.shutil))
            inherited_scope.setitem(vars(consumer), "shutil", view)
            assert consumer.shutil is view
        original = consumer.shutil
        before = dict(vars(original))
        with pytest.MonkeyPatch.context() as scope:
            _fixture(file)(scope)
            assert consumer.shutil.which is original.which
            _assert_namespace(original, before)
        assert consumer.shutil is original
        _assert_namespace(original, before)

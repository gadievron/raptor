"""Exercise actual host-probe fixtures without starting their tool bodies."""
import ast
import copy
from contextlib import contextmanager
from functools import lru_cache
import importlib
from pathlib import Path
import shutil
import subprocess
import sys
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest

from core.testing.module_bindings import patch_module_attribute

_REPO = Path(__file__).resolve().parents[3]
_SPECS = {'core/build/tests/test_toolchain.py': {'attributes': {'shutil': ['which']},
                                        'module': 'core.build.toolchain'},
 'packages/describe/tests/test_package_manager.py': {'attributes': {'shutil': ['which']},
                                                     'module': 'packages.describe.package_manager'},
 'packages/describe/tests/test_tool_readiness.py': {'attributes': {'shutil': ['which']},
                                                    'delegate': 'packages.describe.package_manager',
                                                    'module': 'packages.describe.tool_readiness'},
 'packages/frida/tests/test_active.py': {'attributes': {'subprocess': ['run', 'Popen']},
                                         'module': 'packages.frida.active'},
 'packages/fuzzing/tests/test_env_build.py': {'attributes': {'shutil': ['which']},
                                              'module': 'packages.fuzzing.env_build'},
 'packages/hypothesis_validation/tests/test_adapters_codeql_smt.py': {'attributes': {'shutil': ['which'],
                                                                                     'subprocess': ['run']},
                                                                      'module': 'packages.hypothesis_validation.adapters.codeql'},
 'packages/hypothesis_validation/tests/test_security.py': {'attributes': {'subprocess': ['run']},
                                                           'incidental_tests': ['test_run_passes_output_for_cache_write',
                                                                                'test_codeql_sites_disable_fake_home_but_grant_pack_cache'],
                                                           'module': 'packages.hypothesis_validation.adapters.codeql'}}


@lru_cache(maxsize=None)
def _tree(file):
    return ast.parse((_REPO / file).read_text())


def _patches(file):
    spec = _SPECS[file]
    targets = {binding + "." + attribute for binding, attributes in spec["attributes"].items() for attribute in attributes}
    targets |= {spec["module"] + "." + target for target in targets}
    return sorted((n for n in ast.walk(_tree(file))
                   if isinstance(n, ast.Call) and n.args
                   and (getattr(n.func, "id", "") == "patch" or getattr(n.func, "attr", "") == "patch")
                   and isinstance(n.args[0], ast.Constant) and n.args[0].value in targets),
                  key=lambda n: n.lineno)


def _cases():
    cases = [pytest.param(file, *node.args[0].value.split(".")[-2:], node.args[0].value,
                          id=spec["module"] + "-" + Path(file).stem + "-" + str(index))
             for file, spec in _SPECS.items()
             for index, node in enumerate(_patches(file))]
    for file, spec in _SPECS.items():
        for name in spec.get("incidental_tests", []):
            fn = next(n for n in ast.walk(_tree(file)) if isinstance(n, ast.FunctionDef) and n.name == name)
            expected = spec["module"] + ".subprocess.run"
            found = any(isinstance(n, ast.Call) and n.args and isinstance(n.args[0], ast.Constant) and n.args[0].value == expected for n in ast.walk(fn))
            if not found:
                cases.append(pytest.param(file, "subprocess", "run", None, id="missing-incidental-" + name))
    return cases


def _delegated_cases():
    return [pytest.param(file, "shutil", "which",
                         next(n.args[0].value for n in _patches(file) if n.args[0].value.endswith("shutil.which")),
                         id=spec["module"])
            for file, spec in _SPECS.items() if spec.get("delegate")]


@lru_cache(maxsize=None)
def _fixture(file):
    node = next((n for n in _tree(file).body if isinstance(n, ast.FunctionDef)
                 and n.name == "_isolate_host_probe_patches"), None)
    if node is None:
        return lambda monkeypatch: None  # Original-source negative control.
    node = copy.deepcopy(node)
    node.decorator_list = []
    namespace = {"patch_module_attribute": patch_module_attribute}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])), file, "exec"), namespace)
    return namespace[node.name]


@lru_cache(maxsize=None)
def _module(name):
    with patch.object(sys, "path", sys.path.copy()):
        return importlib.import_module(name)


def _assert_namespace(owner, before):
    current = vars(owner)
    changed = [key for key, value in before.items() if key not in current or current[key] is not value]
    added = sorted(set(current) - set(before))
    assert changed == [] and added == [], (changed, added)


@contextmanager
def _snapshots(file, borrowed):
    spec = _SPECS[file]
    primary = _module(spec["module"])
    delegate = _module(spec["delegate"]) if spec.get("delegate") else primary
    owners = list(dict.fromkeys((primary, delegate)))
    pairs = [(owner, binding) for owner in owners for binding in spec["attributes"]]
    with pytest.MonkeyPatch.context() as inherited_scope:
        for owner, binding in pairs:
            original = getattr(owner, binding)
            assert isinstance(owner, ModuleType) and isinstance(original, ModuleType)
            if borrowed:
                view = ModuleType(original.__name__)
                vars(view).update(vars(original))
                inherited_scope.setitem(vars(owner), binding, view)
        raw = [(owner, dict(vars(owner))) for owner in owners]
        inherited = [(getattr(owner, binding), dict(vars(getattr(owner, binding))))
                     for owner, binding in pairs]
        shared = [(shutil, dict(vars(shutil))), (subprocess, dict(vars(subprocess)))]
        yield primary, delegate, raw, inherited, shared


def _exercise(file, binding, attribute, target, borrowed, exit_mode, delegated=False):
    with _snapshots(file, borrowed) as (primary, delegate, raw, inherited, shared):
        original_delegate = getattr(getattr(delegate, binding), attribute)
        token = object()
        fake = MagicMock(name="owned_probe", return_value=token)
        caught = None
        try:
            with pytest.MonkeyPatch.context() as scope:
                _fixture(file)(scope)
                assert target is not None, "native incidental pack-install context is missing"
                with patch(target, new=fake):
                    for owner, before in shared + inherited:
                        _assert_namespace(owner, before)
                    assert getattr(getattr(primary, binding), attribute) is fake
                    if delegated:
                        forwarded = getattr(getattr(delegate, binding), attribute)
                        assert forwarded is not original_delegate
                        # Invalid real-call arguments refuse before I/O if a
                        # regression reconnects an unmocked implementation.
                        assert forwarded(token, owned=token) is token
                        fake.assert_called_once_with(token, owned=token)
                    if exit_mode != "normal":
                        raise RuntimeError("owned scope exit") if exit_mode == "error" else KeyboardInterrupt("owned scope exit")
        except BaseException as error:
            caught = error
        for owner, before in raw + inherited + shared:
            _assert_namespace(owner, before)
        if exit_mode == "normal":
            assert caught is None, repr(caught)
        else:
            assert isinstance(caught, RuntimeError if exit_mode == "error" else KeyboardInterrupt), repr(caught)
            assert str(caught) == "owned scope exit"


@pytest.mark.parametrize("file,binding,attribute,target", _cases())
@pytest.mark.parametrize("borrowed", [False, True], ids=["ordinary", "borrowed"])
@pytest.mark.parametrize("exit_mode", ["normal", "error", "interrupt"])
def test_native_host_probe_patch_is_owned(file, binding, attribute, target, borrowed, exit_mode):
    _exercise(file, binding, attribute, target, borrowed, exit_mode)


@pytest.mark.parametrize("file,binding,attribute,target", _delegated_cases())
@pytest.mark.parametrize("borrowed", [False, True], ids=["ordinary", "borrowed"])
@pytest.mark.parametrize("exit_mode", ["normal", "error", "interrupt"])
def test_delegated_package_lookup_uses_owned_mock(file, binding, attribute, target, borrowed, exit_mode):
    _exercise(file, binding, attribute, target, borrowed, exit_mode, delegated=True)


_CONTROLS = [
    ("packages/describe/tests/test_package_manager.py", "shutil", "which"),
    ("packages/hypothesis_validation/tests/test_adapters_codeql_smt.py", "subprocess", "run"),
    ("packages/frida/tests/test_active.py", "subprocess", "Popen"),
]


@pytest.mark.parametrize("file,binding,attribute", _CONTROLS)
@pytest.mark.parametrize("borrowed", [False, True])
def test_unmodified_probe_control(file, binding, attribute, borrowed):
    with _snapshots(file, borrowed) as (primary, _, raw, inherited, shared):
        original = getattr(getattr(primary, binding), attribute)
        with pytest.MonkeyPatch.context() as scope:
            _fixture(file)(scope)
            assert getattr(getattr(primary, binding), attribute) is original
            for owner, before in inherited + shared:
                _assert_namespace(owner, before)
        for owner, before in raw + inherited + shared:
            _assert_namespace(owner, before)

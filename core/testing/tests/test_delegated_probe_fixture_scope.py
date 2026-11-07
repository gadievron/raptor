"""Keep native probe mocks and their delegates off shared stdlib modules."""
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

from core.testing.mock_sites import patch_site, patch_target
from core.testing.module_bindings import patch_module_attribute

_REPO = Path(__file__).resolve().parents[3]
_SPECS = {'core/run/tests/test_toolprobe.py': ['core.run.toolprobe',
                                      ['subprocess', 'shutil'],
                                      False],
 'packages/coccinelle/tests/test_runner.py': ['packages.coccinelle.runner',
                                              ['subprocess', 'shutil'],
                                              True],
 'packages/codeql/tests/test_buildless_mode.py': ['packages.codeql.database_manager',
                                                  ['subprocess'],
                                                  True],
 'packages/codeql/tests/test_threat_models.py': ['packages.codeql.query_runner',
                                                 ['subprocess'],
                                                 True],
 'packages/semgrep/tests/test_runner.py': ['packages.semgrep.runner',
                                           ['subprocess', 'shutil'],
                                           True]}


@lru_cache(maxsize=None)
def _tree(file):
    return ast.parse((_REPO / file).read_text())


def _patches(file):
    module, bindings, _ = _SPECS[file]
    targets = {f"{binding}.{attribute}" for binding, attribute in
               (("subprocess", "run"), ("shutil", "which")) if binding in bindings}
    targets |= {module + "." + target for target in targets}
    return sorted((n for n in ast.walk(_tree(file))
                   if patch_target(n) in targets), key=lambda n: n.lineno)



def _cases():
    return [pytest.param(file, *patch_target(node).split(".")[-2:], patch_target(node),
                         id=module + "-" + str(index))
            for file, (module, _, _) in _SPECS.items()
            for index, node in enumerate(_patches(file))]


def _delegated_cases():
    return [pytest.param(file, binding, "run" if binding == "subprocess" else "which",
                         next(patch_target(n) for n in _patches(file)
                              if patch_target(n).split(".")[-2] == binding),
                         id=module + "-" + binding)
            for file, (module, bindings, delegated) in _SPECS.items() if delegated
            for binding in bindings]


@lru_cache(maxsize=None)
def _fixture(file):
    node = next((n for n in _tree(file).body if isinstance(n, ast.FunctionDef)
                 and n.name == "_isolate_probe_patch_targets"), None)
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
    module, bindings, delegated = _SPECS[file]
    primary = _module(module)
    delegate = _module("core.run.toolprobe") if delegated else primary
    owners = list(dict.fromkeys((primary, delegate)))
    pairs = [(owner, binding) for owner in owners for binding in bindings]
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
                node = next(n for n in _patches(file) if patch_target(n) == target)
                with patch_site(node, target, fake):
                    for owner, before in shared + inherited:
                        _assert_namespace(owner, before)
                    assert getattr(getattr(primary, binding), attribute) is fake
                    if delegated:
                        forwarded = getattr(getattr(delegate, binding), attribute)
                        assert forwarded is not original_delegate
                        # An invalid real-call signature fails before I/O if a
                        # regression accidentally reconnects the real function.
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
def test_native_probe_patch_is_owned(file, binding, attribute, target, borrowed, exit_mode):
    _exercise(file, binding, attribute, target, borrowed, exit_mode)


@pytest.mark.parametrize("file,binding,attribute,target", _delegated_cases())
@pytest.mark.parametrize("borrowed", [False, True], ids=["ordinary", "borrowed"])
@pytest.mark.parametrize("exit_mode", ["normal", "error", "interrupt"])
def test_delegated_probe_uses_owned_mock(file, binding, attribute, target, borrowed, exit_mode):
    _exercise(file, binding, attribute, target, borrowed, exit_mode, delegated=True)


@pytest.mark.parametrize("binding,attribute", [("subprocess", "run"), ("shutil", "which")])
@pytest.mark.parametrize("borrowed", [False, True])
def test_unmodified_probe_control(binding, attribute, borrowed):
    file = next(iter(_SPECS))
    with _snapshots(file, borrowed) as (primary, _, raw, inherited, shared):
        original = getattr(getattr(primary, binding), attribute)
        with pytest.MonkeyPatch.context() as scope:
            _fixture(file)(scope)
            assert getattr(getattr(primary, binding), attribute) is original
            for owner, before in inherited + shared:
                _assert_namespace(owner, before)
        for owner, before in raw + inherited + shared:
            _assert_namespace(owner, before)

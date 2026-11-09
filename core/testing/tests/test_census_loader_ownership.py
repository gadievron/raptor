"""Census loader ownership checks using the real data predicates."""
import ast
import builtins
from contextlib import contextmanager
import copy
import functools
import importlib.util
from pathlib import Path
import sys
from types import FunctionType, ModuleType, SimpleNamespace
import unittest

import pytest
from core.testing.module_registry import module_registry_scope
from core.testing.module_state import isolated_module_state
from core.testing.module_views import module_function_view

_ROOT = Path(__file__).resolve().parents[3]
_FILE = '.github/tests/test_redos_idiom_census.py'
_SOURCE = _ROOT / _FILE


@pytest.fixture(scope='module')
def census():
    name = '_owned_census_data_predicates'
    with module_registry_scope(name) as modules:
        spec = importlib.util.spec_from_file_location(name, _ROOT / _FILE)
        module = importlib.util.module_from_spec(spec)
        modules[name] = module
        spec.loader.exec_module(module)
        yield module


@functools.lru_cache(maxsize=1)
def _tree():
    return ast.parse(_SOURCE.read_text())


def _compile(name, namespace, owner=None):
    scope = _tree()
    if owner is not None:
        scope = next(n for n in scope.body if isinstance(n, ast.ClassDef) and n.name == owner)
    node = copy.deepcopy(next(n for n in ast.walk(scope) if isinstance(n, ast.FunctionDef) and n.name == name))
    node.decorator_list = []
    exec(compile(ast.Module(body=[node], type_ignores=[]), _FILE, 'exec'), namespace)
    return namespace[name]


def _views(state):
    from core.security import prompt_input_preflight
    from packages.sca.supply_chain import exfil_destinations

    pf = module_function_view(prompt_input_preflight)
    exfil = module_function_view(exfil_destinations)
    exfil._RULES_CACHE = None
    if state == 'empty':
        exfil._RULES_CACHE = []
    elif state == 'warm':
        assert exfil._load_rules()
    return pf, exfil


def _helper(patcher):
    raw = isolated_module_state.__wrapped__
    clone = FunctionType(raw.__code__, {**raw.__globals__, 'pytest': SimpleNamespace(MonkeyPatch=patcher)}, argdefs=raw.__defaults__)
    clone.__kwdefaults__ = raw.__kwdefaults__
    return contextmanager(clone)


def _namespace(census, pf, exfil, helper):
    def importing(name, globals=None, locals=None, fromlist=(), level=0):
        if name == 'core.security':
            return SimpleNamespace(prompt_input_preflight=pf)
        if name == 'core.security.prompt_input_preflight':
            return pf
        if name == 'packages.sca.supply_chain':
            return SimpleNamespace(exfil_destinations=exfil)
        if name == 'core.testing.module_state':
            return SimpleNamespace(isolated_module_state=helper)
        return builtins.__import__(name, globals, locals, fromlist, level)
    namespace = {**vars(census), '__builtins__': {**vars(builtins), '__import__': importing}}
    _compile('_data_file_loaders', namespace)
    _compile('_data_file_members', namespace)
    return namespace


@pytest.mark.parametrize('path_kind', ['list', 'tuple', 'duplicate'])
@pytest.mark.parametrize('outcome', ['normal', 'error', 'interrupt'])
def test_loader_restores_borrowed_path_on_import_failure(census, path_kind, outcome):
    pf, exfil = _views('none')
    namespace = _namespace(census, pf, exfil, isolated_module_state)
    view = ModuleType('owned_sys')
    borrowed = ('caller', str(_ROOT)) if path_kind == 'tuple' else [str(_ROOT), 'caller', str(_ROOT)] if path_kind == 'duplicate' else ['caller']
    view.path = borrowed
    contents = tuple(borrowed)
    namespace['sys'] = view
    failure = RuntimeError('owned import failed') if outcome == 'error' else KeyboardInterrupt('owned import interrupted')
    actual_import = namespace['__builtins__']['__import__']
    reached = []
    def importing(name, globals=None, locals=None, fromlist=(), level=0):
        if name in ('core.security.prompt_input_preflight', 'packages.sca.supply_chain'):
            assert view.path is not borrowed and view.path[0] == str(_ROOT)
            reached.append(name)
            if name == 'packages.sca.supply_chain' and outcome != 'normal':
                raise failure
        return actual_import(name, globals, locals, fromlist, level)
    namespace['__builtins__'] = {**vars(builtins), '__import__': importing}
    function = _compile('_data_file_loaders', namespace)
    if outcome == 'normal':
        loader, module = function()
        assert loader is pf._load_patterns and module is exfil
    else:
        with pytest.raises(type(failure)) as caught:
            function()
        assert caught.value is failure
    assert len(reached) == 2
    assert view.path is borrowed and tuple(borrowed) == contents


@pytest.mark.parametrize('state', ['none', 'empty', 'warm'])
@pytest.mark.parametrize('mode', ['normal', 'body_error', 'body_interrupt', 'setup_error', 'setup_interrupt'])
def test_members_preserve_borrowed_exfil_cache(census, state, mode):
    pf, exfil = _views(state)
    borrowed = exfil._RULES_CACHE
    contents = borrowed.copy() if borrowed is not None else None
    failure = KeyboardInterrupt('owned interruption') if mode.endswith('interrupt') else RuntimeError('owned failure')
    publications, reached = [], []
    class Patcher(pytest.MonkeyPatch):
        def setattr(self, obj, name, value, *args, **kwargs):
            super().setattr(obj, name, value, *args, **kwargs)
            if obj is exfil and name == '_RULES_CACHE':
                publications.append(name)
                if mode.startswith('setup_'):
                    raise failure
    actual = exfil._load_rules
    def loading():
        result = actual()
        assert result and exfil._RULES_CACHE is not borrowed
        reached.append(True)
        if mode.startswith('body_'):
            raise failure
        return result
    exfil._load_rules = loading
    namespace = _namespace(census, pf, exfil, _helper(Patcher))
    function = namespace['_data_file_members']
    if mode == 'normal':
        assert isinstance(function(), list)
    else:
        with pytest.raises(type(failure)) as caught:
            function()
        assert caught.value is failure
    assert publications
    assert bool(reached) is (not mode.startswith('setup_'))
    assert exfil._RULES_CACHE is borrowed and borrowed == contents


def _self_cases():
    for kind in ('pattern', 'exfil'):
        for state in ('none', 'empty', 'warm'):
            for mode in ('normal', 'body_error', 'body_interrupt'):
                yield pytest.param(kind, state, mode, None, id=f'{kind}-{state}-{mode}')
            for field in ('_PATTERNS_DIR',) if kind == 'pattern' else ('_DATA_FILE', '_RULES_CACHE'):
                for mode in ('setup_error', 'setup_interrupt'):
                    yield pytest.param(kind, state, mode, field, id=f'{kind}-{state}-{mode}-{field}')


@pytest.mark.parametrize('kind,state,mode,fault_field', list(_self_cases()))
def test_planted_selfchecks_restore_paths_and_cache(census, kind, state, mode, fault_field):
    pf, exfil = _views(state)
    borrowed = pf._PATTERNS_DIR, exfil._DATA_FILE, exfil._RULES_CACHE
    contents = borrowed[2].copy() if borrowed[2] is not None else None
    path, path_contents = sys.path, sys.path.copy()
    failure = KeyboardInterrupt('owned interruption') if mode.endswith('interrupt') else RuntimeError('owned failure')
    publications, reached = [], []
    class Patcher(pytest.MonkeyPatch):
        def setattr(self, obj, name, value, *args, **kwargs):
            super().setattr(obj, name, value, *args, **kwargs)
            if (obj is pf and name == '_PATTERNS_DIR') or (obj is exfil and name in ('_DATA_FILE', '_RULES_CACHE')):
                publications.append(name)
                if mode.startswith('setup_') and name == fault_field:
                    raise failure
    namespace = _namespace(census, pf, exfil, _helper(Patcher))
    actual = namespace['_data_file_members']
    def members():
        result = actual()
        if kind == 'pattern':
            assert pf._PATTERNS_DIR is not borrowed[0]
            assert any('planted_member' in pattern for stem, pattern in result)
        else:
            assert exfil._DATA_FILE is not borrowed[1]
            assert any('evil' in pattern for stem, pattern in result)
        reached.append(True)
        if mode.startswith('body_'):
            raise failure
        return result
    namespace['_data_file_members'] = members
    name = ('test_data_file_arm_detects_a_planted_member' if kind == 'pattern'
            else 'test_data_file_arm_detects_a_planted_exfil_member')
    function = _compile(name, namespace)
    if mode == 'normal':
        function(unittest.TestCase())
    else:
        with pytest.raises(type(failure)) as caught:
            function(unittest.TestCase())
        assert caught.value is failure
    assert publications
    assert bool(reached) is (not mode.startswith('setup_'))
    assert pf._PATTERNS_DIR is borrowed[0] and exfil._DATA_FILE is borrowed[1]
    assert exfil._RULES_CACHE is borrowed[2] and borrowed[2] == contents
    assert sys.path is path and sys.path == path_contents


def test_actual_loader_retains_duplicate_paths_and_blocked_http_dependency(monkeypatch):
    import ast
    from pathlib import Path
    from typing import Any
    from unittest.mock import patch
    from core.testing.module_registry import fresh_module_tree, module_registry_scope

    root = Path(__file__).resolve().parents[3]
    file = root / _FILE
    node = next(n for n in ast.parse(file.read_text()).body if isinstance(n, ast.FunctionDef) and n.name == '_data_file_loaders')
    namespace = {'sys': sys, '_REPO': root, '_path_patch': patch, 'Any': Any}
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(file), 'exec'), namespace)
    borrowed_path = [*sys.path, str(root), str(root)]
    contents = list(borrowed_path)
    with monkeypatch.context() as owned:
        owned.setattr(sys, 'path', borrowed_path)
        with fresh_module_tree('packages.sca'), fresh_module_tree('core.http'), module_registry_scope('urllib3', 'urllib3.exceptions'):
            owned.setitem(sys.modules, 'urllib3', None)
            owned.setitem(sys.modules, 'urllib3.exceptions', None)
            load_patterns, exfil = namespace['_data_file_loaders']()
            assert load_patterns() and exfil._load_rules()
            assert sys.path is borrowed_path and sys.path == contents
            assert sys.modules['urllib3'] is None
            assert sys.modules['urllib3.exceptions'] is None
            assert 'core.http.urllib_backend' not in sys.modules


@pytest.mark.parametrize('state', ['none', 'empty', 'warm'])
@pytest.mark.parametrize('mode', ['normal', 'body_error', 'body_interrupt', 'setup_error', 'setup_interrupt'])
def test_nested_data_arm_preserves_borrowed_exfil_cache(census, state, mode):
    pf, exfil = _views(state)
    borrowed = exfil._RULES_CACHE
    contents = borrowed.copy() if borrowed is not None else None
    failure = KeyboardInterrupt('owned interruption') if mode.endswith('interrupt') else RuntimeError('owned failure')
    publications, reached = [], []

    class Patcher(pytest.MonkeyPatch):
        def setattr(self, obj, name, value, *args, **kwargs):
            super().setattr(obj, name, value, *args, **kwargs)
            if obj is exfil and name == '_RULES_CACHE':
                publications.append(name)
                if mode.startswith('setup_'):
                    raise failure

    actual = exfil._load_rules

    def loading():
        result = actual()
        assert result and exfil._RULES_CACHE is not borrowed
        reached.append(True)
        if mode.startswith('body_'):
            raise failure
        return result

    exfil._load_rules = loading
    namespace = _namespace(census, pf, exfil, _helper(Patcher))
    function = _compile('test_pattern_data_files_have_no_members', namespace,
                        owner='NestedQuantifierCensus')
    if mode == 'normal':
        function(unittest.TestCase())
    else:
        with pytest.raises(type(failure)) as caught:
            function(unittest.TestCase())
        assert caught.value is failure
    assert publications
    assert bool(reached) is (not mode.startswith('setup_'))
    assert exfil._RULES_CACHE is borrowed and borrowed == contents

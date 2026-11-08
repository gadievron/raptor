"""Dependency mocks preserve unrelated module-cache activity in native suites."""

import ast
from functools import lru_cache
import json
from pathlib import Path
import sys
import threading
from types import ModuleType
import types
from unittest import mock
from uuid import uuid4

import pytest

from core.testing import module_registry as registry
from core.testing.module_bindings import patch_module_attribute

_ROOT = Path(__file__).resolve().parents[3]
_SITES = json.loads((Path(__file__).parent / 'data/module_registry_mock_sites.json').read_text())
_BASELINE = None
_MISSING = object()


def _is_mock_call(node):
    if not isinstance(node, ast.Call):
        return False
    if isinstance(node.func, ast.Name) and node.func.id == 'mock_module_registry':
        return True
    if not isinstance(node.func, ast.Attribute) or node.func.attr != 'dict' or not node.args:
        return False
    first = node.args[0]
    return ((isinstance(first, ast.Constant) and first.value == 'sys.modules')
            or (isinstance(first, ast.Attribute) and first.attr == 'modules'
                and isinstance(first.value, ast.Name) and first.value.id in ('sys', '_sys')))


@lru_cache(maxsize=None)
def _calls(file):
    source = ((_BASELINE or _ROOT) / file).read_text()
    tree = ast.parse(source)
    return sorted((node for node in ast.walk(tree) if _is_mock_call(node)), key=lambda n: n.lineno)


def _prior(owner, name, state):
    previous = None if state == 'negative' else ModuleType(name)
    # setitem registers even the absent case before its deliberate removal.
    owner.setitem(sys.modules, name, previous)
    if state == 'missing':
        del sys.modules[name]
        return _MISSING
    return previous


def _assert_prior(expected):
    for name, previous in expected.items():
        if previous is _MISSING:
            assert name not in sys.modules, name
        else:
            assert sys.modules[name] is previous, name


def _context(case):
    node = _calls(case['file'])[case['ordinal']]
    namespace = dict(mock_module_registry=registry.mock_module_registry, sys=sys, _sys=sys,
                     mock=mock, patch=mock.patch, _patch=mock.patch, mock_patch=mock.patch,
                     MagicMock=mock.MagicMock, types=types)
    for name in {n.id for n in ast.walk(node) if isinstance(n, ast.Name)} - namespace.keys():
        fake = ModuleType(name)
        fake.api = ModuleType(name + '.api')
        namespace[name] = fake
    # Evaluate the native mapping, including its constructors and paired aliases.
    mapping = node.args[-1]
    assert [ast.literal_eval(key) for key in mapping.keys] == case['names']
    return eval(compile(ast.Expression(body=node), case['file'], 'eval'), namespace)


def _foreign_changes(owner):
    names = ['_owned_foreign_' + uuid4().hex for _ in range(3)]
    initial, replacement = ModuleType(names[1]), ModuleType(names[1])
    owner.setitem(sys.modules, names[1], initial)
    owner.setitem(sys.modules, names[2], ModuleType(names[2]))
    published = ModuleType(names[0])
    errors = []

    def publish():
        try:
            owner.setitem(sys.modules, names[0], published)
            owner.setitem(sys.modules, names[1], replacement)
            owner.delitem(sys.modules, names[2])
        except BaseException as error:
            errors.append(error)

    def run():
        worker = threading.Thread(target=publish)
        try:
            worker.start()
        finally:
            if worker.ident is not None:
                worker.join(5)
                assert not worker.is_alive(), 'module-cache writer survived'
        assert not errors

    def check():
        assert sys.modules.get(names[0]) is published, 'unrelated new import was removed'
        assert sys.modules.get(names[1]) is replacement, 'unrelated replacement was rolled back'
        assert names[2] not in sys.modules, 'unrelated deletion was rolled back'

    return run, check


def test_native_mock_inventory_is_exact():
    for file in dict.fromkeys(row['file'] for row in _SITES):
        cases = [row for row in _SITES if row['file'] == file]
        calls = _calls(file)
        assert len(calls) == len(cases), file
        assert [[ast.literal_eval(key) for key in call.args[-1].keys] for call in calls] == [row['names'] for row in cases]


@pytest.mark.parametrize('case', _SITES, ids=lambda row: row['file'] + '::' + row['symbol'] + ':' + str(row['ordinal']))
@pytest.mark.parametrize('state', ['missing', 'negative', 'borrowed'])
@pytest.mark.parametrize('outcome', ['normal', 'error', 'interrupt'])
def test_native_dependency_mock_preserves_other_module_writers(case, state, outcome, monkeypatch):
    expected = {name: _prior(monkeypatch, name, state) for name in case['names']}
    publish, check = _foreign_changes(monkeypatch)
    failure = RuntimeError('native consumer failed') if outcome == 'error' else KeyboardInterrupt('native consumer interrupted')
    context = _context(case)

    def consume():
        with context as modules:
            assert modules is sys.modules
            assert all(name in modules for name in case['names'])
            # The returned table is live, as required by the radare2 fake setup.
            first = case['names'][0]
            modules[first] = ModuleType(first)
            publish()
            if outcome != 'normal':
                raise failure

    if outcome == 'normal':
        consume()
    else:
        with pytest.raises(type(failure)) as caught:
            consume()
        assert caught.value is failure
    _assert_prior(expected)
    check()


@pytest.mark.parametrize('state', ['missing', 'negative', 'borrowed'])
@pytest.mark.parametrize('outcome', ['normal', 'error', 'interrupt'])
def test_nested_dependency_mocks_restore_outer_then_borrowed_state(state, outcome, monkeypatch):
    name = '_owned_nested_' + uuid4().hex
    previous = {name: _prior(monkeypatch, name, state)}
    outer, inner = ModuleType(name), ModuleType(name)
    failure = RuntimeError('inner failed') if outcome == 'error' else KeyboardInterrupt('inner interrupted')
    with registry.mock_module_registry({name: outer}):
        def consume():
            with registry.mock_module_registry({name: inner}):
                assert sys.modules[name] is inner
                if outcome != 'normal':
                    raise failure
        if outcome == 'normal':
            consume()
        else:
            with pytest.raises(type(failure)) as caught:
                consume()
            assert caught.value is failure
        assert sys.modules[name] is outer
    _assert_prior(previous)


@pytest.mark.parametrize('position', [0, 1, 2])
@pytest.mark.parametrize('failure_type', [RuntimeError, KeyboardInterrupt])
def test_partial_mock_publication_restores_all_selected_entries(position, failure_type):
    previous = [ModuleType('borrowed_' + str(i)) for i in range(3)]
    failure = failure_type('publication failed')

    class Table(dict):
        def __setitem__(self, name, value):
            super().__setitem__(name, value)
            if name == str(position) and value is None:
                raise failure

    table = Table({str(i): module for i, module in enumerate(previous)})
    with pytest.MonkeyPatch.context() as owner:
        patch_module_attribute(owner, registry, 'sys', 'modules', table)
        with pytest.raises(failure_type) as caught:
            with registry.mock_module_registry(dict.fromkeys(('0', '1', '2'))):
                pytest.fail('partially published mock reached its consumer')
        assert caught.value is failure
    assert all(table[str(i)] is value for i, value in enumerate(previous))


@pytest.mark.parametrize('outcome', ['normal', 'error', 'interrupt'])
def test_empty_mock_leaves_all_module_cache_writes_live(outcome, monkeypatch):
    publish, check = _foreign_changes(monkeypatch)
    failure = RuntimeError('body failed') if outcome == 'error' else KeyboardInterrupt('body interrupted')
    def consume():
        with registry.mock_module_registry({}):
            publish()
            if outcome != 'normal':
                raise failure
    if outcome == 'normal':
        consume()
    else:
        with pytest.raises(type(failure)):
            consume()
    check()


def _direct_bootstraps():
    files = dict.fromkeys(row['file'] for row in _SITES)
    return [file for file in files
            if any(isinstance(node, ast.Call) and ast.unparse(node.func) == 'sys.path.insert'
                   for statement in ast.parse((_ROOT / file).read_text()).body
                   if isinstance(statement, ast.If)
                   for node in ast.walk(statement))]


@pytest.mark.parametrize('file', _direct_bootstraps())
def test_mock_helper_import_follows_direct_script_bootstrap(file, monkeypatch):
    import builtins

    tree = ast.parse((_ROOT / file).read_text())
    helper = next(node for node in tree.body if isinstance(node, ast.ImportFrom)
                  and node.module == 'core.testing.module_registry')
    tree.body = [node for node in tree.body if node.lineno <= helper.lineno]
    seen = []

    def importing(name, *args, **kwargs):
        if name == 'core.testing.module_registry':
            assert str(_ROOT) in sys.path, 'test helper imported before direct-script bootstrap'
            seen.append(name)
        return builtins.__import__(name, *args, **kwargs)

    monkeypatch.setattr(sys, 'path', [entry for entry in sys.path
                                    if Path(entry or '.').resolve() != _ROOT])
    namespace = dict(__name__='__main__', __file__=str(_ROOT / file),
                     __builtins__={**vars(builtins), '__import__': importing})
    exec(compile(tree, str(_ROOT / file), 'exec'), namespace)
    assert seen == ['core.testing.module_registry']

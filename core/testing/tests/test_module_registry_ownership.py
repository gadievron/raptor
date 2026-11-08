"""Native helper loaders own exact aliases through setup and consumption."""

import ast
from contextlib import contextmanager
from functools import lru_cache
import importlib.machinery
import importlib.util
import inspect
import json
import os
from pathlib import Path
import sys
import threading
from types import ModuleType
from typing import get_type_hints
from unittest.mock import patch
from uuid import uuid4

import pytest

from core.testing import module_registry as registry
from core.testing.module_bindings import patch_module_attribute

_ROOT = Path(__file__).resolve().parents[3]
_SITES = json.loads((Path(__file__).parent / 'data/module_registry_sites.json').read_text())
_BASELINE = None
_MISSING = object()


def _source(file):
    return ((_BASELINE / file).read_text() if _BASELINE is not None else (_ROOT / file).read_text())


@lru_cache(maxsize=None)
def _function(file, name):
    tree = ast.parse(_source(file))
    node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name)
    node.decorator_list = []
    return compile(ast.Module(body=[node], type_ignores=[]), file, 'exec')


@lru_cache(maxsize=None)
def _prefix(file):
    tree = ast.parse(_source(file))
    stop = next((n.lineno for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))), 10**9)
    tree.body = [n for n in tree.body if n.lineno < stop]
    return compile(tree, file, 'exec')


def _prior(owner, name, state):
    if state == 'missing':
        owner.delitem(sys.modules, name, raising=False)
        return _MISSING
    previous = None if state == 'negative' else ModuleType(name)
    owner.setitem(sys.modules, name, previous)
    return previous


def _assert_prior(expected):
    for name, previous in expected.items():
        if previous is _MISSING:
            assert name not in sys.modules, name
        else:
            assert sys.modules[name] is previous, name


@contextmanager
def _fixture(function):
    result = function()
    if inspect.isgenerator(result):
        try:
            yield next(result)
        finally:
            result.close()
    else:
        yield result


class _ForeignImport:
    def __init__(self, owner):
        self.owner = owner
        self.name = '_owned_foreign_dependency_' + uuid4().hex
        self.module = None

    def publish(self):
        errors = []

        def other_importer():
            try:
                self.module = ModuleType(self.name)
                self.owner.setitem(sys.modules, self.name, self.module)
            except BaseException as error:
                errors.append(error)

        worker = threading.Thread(target=other_importer)
        try:
            worker.start()
        finally:
            if worker.ident is not None:
                worker.join(5)
                assert not worker.is_alive(), 'independent importer survived'
        assert not errors

    def assert_live(self):
        assert self.module is not None
        assert sys.modules.get(self.name) is self.module


def _script(hook, outcome):
    return (
        'from __future__ import annotations\n'
        'from dataclasses import dataclass\n'
        'import sys\n'
        f'control = sys.modules[{hook!r}]\n'
        'if control.audit: assert __import__("os").environ["_RAPTOR_TRUSTED"] == "1"\n'
        '@dataclass\n'
        'class Record:\n'
        '    next: Record | None = None\n'
        'control.foreign.publish()\n'
        + ('raise control.failure\n' if outcome != 'normal' else '')
    )


@pytest.mark.parametrize('case', _SITES['fixtures'], ids=lambda row: row['file'])
@pytest.mark.parametrize('state', ['missing', 'negative', 'borrowed'])
@pytest.mark.parametrize('marker', [None, '', 'borrowed'], ids=['missing', 'empty', 'borrowed'])
@pytest.mark.parametrize('outcome', ['normal', 'error', 'interrupt'])
def test_native_fixture_restores_borrowed_alias(case, state, marker, outcome, tmp_path, monkeypatch):
    file, name, alias = case['file'], case['fixture'], case['alias']
    if marker is None:
        monkeypatch.delenv('_RAPTOR_TRUSTED', raising=False)
    else:
        monkeypatch.setenv('_RAPTOR_TRUSTED', marker)
    expected = {alias: _prior(monkeypatch, alias, state)}
    foreign = _ForeignImport(monkeypatch)
    hook = ModuleType('_owned_loader_control_' + uuid4().hex)
    hook.audit = file.startswith('core/audit/')
    hook.foreign = foreign
    hook.failure = RuntimeError('native import failed') if outcome == 'error' else KeyboardInterrupt('native import interrupted')
    monkeypatch.setitem(sys.modules, hook.__name__, hook)
    script = tmp_path / ('test_redos_idiom_census.py' if name == 'census' else 'helper.py')
    script.write_text(_script(hook.__name__, outcome))
    namespace = dict(__name__='owned_fixture', __file__=str(tmp_path/'test_native.py'),
                     _SCRIPT=script, importlib=importlib, Path=Path, sys=sys, os=os,
                     pytest=pytest, patch=patch, module_registry_scope=registry.module_registry_scope)
    exec(_function(file, name), namespace)
    before = dict(os.environ), sys.path, list(sys.path)
    if outcome == 'normal':
        with _fixture(namespace[name]) as module:
            assert sys.modules[alias] is module
            assert get_type_hints(module.Record)['next'] == module.Record | None
    else:
        with pytest.raises(type(hook.failure)) as caught:
            with _fixture(namespace[name]):
                pytest.fail('the injected import failure was not reached')
        assert caught.value is hook.failure
    _assert_prior(expected)
    foreign.assert_live()
    assert dict(os.environ) == before[0]
    assert sys.path is before[1] and sys.path == before[2]


_COLLECTION = _SITES['collection'] + _SITES['scoped_imports']


def _collection_files(root, hook, outcome):
    paths = [
        'packages/static-analysis/compiler_scan.py',
        '.devcontainer/debian_cargo_notices.py', '.devcontainer/cargo_notice_inventory.py',
        '.github/scripts/report_sbom_licenses.py', '.github/scripts/ci_change_scope.py',
        '.github/scripts/dockerhub_scope.py', '.github/scripts/repo_invariant_scope.py',
        '.github/scripts/update_published_image_docs.py',
    ]
    for file in paths:
        path = root / file
        path.parent.mkdir(parents=True, exist_ok=True)
        source = _script(hook, outcome)
        if file.endswith('cargo_notice_inventory.py'):
            source += 'import debian_cargo_notices; RELATED = debian_cargo_notices.Record\n'
        if file.endswith('dockerhub_scope.py'):
            source += 'import ci_change_scope; RELATED = ci_change_scope.Record\n'
        path.write_text(source)


def _namespace(case, root):
    return {'__name__': 'owned_collection', '__file__': str(root / case['file'])}


def _aliases(case, namespace):
    return {eval(expression, namespace) if expression.endswith('.name') else expression: namespace[variable]
            for expression, variable in case['bindings']}


def _alias_names(case):
    if 'bindings' in case and case in _SITES['scoped_imports']:
        return [name for name, _ in case['bindings']]
    # Spec construction is side-effect-free; evaluate the actual spec setup
    # without loading the helper or publishing its alias.
    tree = ast.parse((_ROOT / case['file']).read_text())
    names = []
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            call = node.value
            if ast.unparse(call.func) == 'importlib.util.spec_from_file_location':
                names.append(ast.literal_eval(call.args[0]))
    return names


@pytest.mark.parametrize('case', _COLLECTION, ids=lambda row: row['file'])
@pytest.mark.parametrize('state', ['missing', 'negative', 'borrowed'])
@pytest.mark.parametrize('outcome', ['normal', 'error', 'interrupt'])
def test_native_collection_preserves_aliases_and_other_imports(case, state, outcome, tmp_path, monkeypatch):
    file = case['file']
    foreign = _ForeignImport(monkeypatch)
    hook = ModuleType('_owned_loader_control_' + uuid4().hex)
    hook.audit, hook.foreign = False, foreign
    hook.failure = RuntimeError('native import failed') if outcome == 'error' else KeyboardInterrupt('native import interrupted')
    monkeypatch.setitem(sys.modules, hook.__name__, hook)
    _collection_files(tmp_path, hook.__name__, outcome)
    expected = {name: _prior(monkeypatch, name, state) for name in _alias_names(case)}
    namespace = _namespace(case, tmp_path)
    # Warm only ordinary imports, before borrowing caller state.
    tree = ast.parse(_source(file))
    imports = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
    exec(compile(ast.Module(body=imports, type_ignores=[]), file, 'exec'), namespace)
    before = dict(os.environ), sys.path, list(sys.path)
    if outcome == 'normal':
        exec(_prefix(file), namespace)
        for module in _aliases(case, namespace).values():
            assert module.Record().next is None
        if 'debian' in namespace:
            assert namespace['tool'].RELATED is namespace['debian'].Record
        if 'changes' in namespace:
            assert namespace['image'].RELATED is namespace['changes'].Record
    else:
        with pytest.raises(type(hook.failure)) as caught:
            exec(_prefix(file), namespace)
        assert caught.value is hook.failure
    _assert_prior(expected)
    foreign.assert_live()
    assert dict(os.environ) == before[0]
    assert sys.path is before[1] and sys.path == before[2]


@pytest.mark.parametrize('case', _COLLECTION, ids=lambda row: row['file'])
@pytest.mark.parametrize('state', ['missing', 'negative', 'borrowed'])
@pytest.mark.parametrize('outcome', ['normal', 'error', 'interrupt'])
def test_native_runtime_scope_keeps_dataclass_binding(case, state, outcome, tmp_path, monkeypatch):
    foreign = _ForeignImport(monkeypatch)
    hook = ModuleType('_owned_loader_control_' + uuid4().hex)
    hook.audit, hook.foreign, hook.failure = False, foreign, None
    monkeypatch.setitem(sys.modules, hook.__name__, hook)
    _collection_files(tmp_path, hook.__name__, 'normal')
    namespace = _namespace(case, tmp_path)
    exec(_prefix(case['file']), namespace)
    modules = _aliases(case, namespace)
    expected = {name: _prior(monkeypatch, name, state) for name in modules}
    exec(_function(case['file'], '_registered_helpers'), namespace)
    failure = RuntimeError('consumer failed') if outcome == 'error' else KeyboardInterrupt('consumer interrupted')

    def consume():
        with _fixture(namespace['_registered_helpers']):
            for name, module in modules.items():
                assert sys.modules[name] is module
                assert get_type_hints(module.Record)['next'] == module.Record | None
            if outcome != 'normal':
                raise failure

    if outcome == 'normal':
        consume()
    else:
        with pytest.raises(type(failure)) as caught:
            consume()
        assert caught.value is failure
    _assert_prior(expected)
    foreign.assert_live()


@pytest.mark.parametrize('state', ['missing', 'negative', 'borrowed'])
@pytest.mark.parametrize('outcome', ['normal', 'error', 'interrupt'])
@pytest.mark.parametrize('count', [1, 3])
def test_selected_registry_slots_restore_without_clearing_foreign_entries(state, outcome, count, monkeypatch):
    names = ['_owned_module_slot_' + uuid4().hex for _ in range(count)]
    expected = {name: _prior(monkeypatch, name, state) for name in names}
    foreign = _ForeignImport(monkeypatch)
    failure = RuntimeError('body failed') if outcome == 'error' else KeyboardInterrupt('body interrupted')

    def consume():
        with registry.module_registry_scope(*names) as table:
            assert table is sys.modules
            for name in names:
                table[name] = ModuleType(name)
            foreign.publish()
            if outcome != 'normal':
                raise failure

    if outcome == 'normal':
        consume()
    else:
        with pytest.raises(type(failure)) as caught:
            consume()
        assert caught.value is failure
    _assert_prior(expected)
    foreign.assert_live()


@pytest.mark.parametrize('position', [0, 1, 2])
@pytest.mark.parametrize('failure_type', [RuntimeError, KeyboardInterrupt])
def test_partial_publication_and_interrupted_restoration_attempt_every_slot(position, failure_type, monkeypatch):
    previous = [ModuleType('borrowed_'+str(i)) for i in range(3)]
    failure = failure_type('registry update interrupted')

    for stage in ('publish', 'restore'):
        visited = []

        class Table(dict):
            def __setitem__(self, name, value):
                super().__setitem__(name, value)
                if value is previous[int(name)]:
                    visited.append(name)
                if name == str(position) and ((stage == 'publish' and value is None)
                                              or (stage == 'restore' and value is previous[position])):
                    raise failure

        table = Table({str(i): value for i, value in enumerate(previous)})
        with pytest.MonkeyPatch.context() as patcher:
            patch_module_attribute(patcher, registry, 'sys', 'modules', table)
            with pytest.raises(failure_type) as caught:
                with registry.module_registry_scope('0', '1', '2') as owned:
                    for name in ('0', '1', '2'):
                        owned[name] = None
            assert caught.value is failure
        assert all(table[str(i)] is value for i, value in enumerate(previous))
        assert set(visited) == {'0', '1', '2'}


@pytest.mark.slow
@pytest.mark.parametrize('method', [
    'test_flag_parses_and_reaches_the_command',
    'test_negative_value_refused_at_parse_time',
])
def test_real_resume_cli_owns_stale_launch_state(method, tmp_path, monkeypatch):
    from core.audit.tests import test_resume_max_cost as native

    monkeypatch.setenv('_RAPTOR_SCRATCH_AUTH', 'invalid-inherited-authorisation')
    monkeypatch.setenv('RAPTOR_SESSION_PID', '999999')
    monkeypatch.setenv('RAPTOR_SESSION_TOKEN', 'invalid-inherited-session')
    before = dict(os.environ)
    getattr(native.TestResumeParserAcceptsMaxCost(), method)(tmp_path)
    assert dict(os.environ) == before

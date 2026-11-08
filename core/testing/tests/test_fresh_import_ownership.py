"""Fresh-import probes restore aliases, raw parent bindings and borrowed caches."""

import ast
import builtins
from contextlib import contextmanager, nullcontext
import copy
from functools import lru_cache
import importlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
from tempfile import TemporaryDirectory
from types import ModuleType, SimpleNamespace
from typing import get_type_hints
import unittest
from unittest.mock import patch
from uuid import uuid4

import pytest

from core.testing import module_registry as registry
from core.testing.module_bindings import patch_module_attribute
from core.testing.module_state import isolated_module_state

_ROOT = Path(__file__).resolve().parents[3]
_SITES = json.loads((Path(__file__).parent / 'data/fresh_import_sites.json').read_text())
_BASELINE = None
_MISSING = object()


@lru_cache(maxsize=None)
def _tree(file):
    return ast.parse(((_BASELINE or _ROOT) / file).read_text())


def _function(file, name, namespace, *, window=False):
    node = copy.deepcopy(next(n for n in ast.walk(_tree(file)) if isinstance(n, ast.FunctionDef) and n.name == name))
    node.decorator_list = []
    if window:
        node.args = ast.arguments(posonlyargs=[], args=[], kwonlyargs=[], kw_defaults=[], defaults=[])
        node.returns = None
        if not any(isinstance(n, ast.Yield) for n in ast.walk(node)):
            # Replay the native inline purge around a yield instead of its
            # domain payload. The native domain suite runs separately.
            owner = next(n for n in node.body if isinstance(n, (ast.Try, ast.With)))
            owner.body = [ast.Expr(value=ast.Yield(value=None))]
            node.body = [n for n in node.body if not isinstance(n, ast.Import)]
    ast.fix_missing_locations(node)
    exec(compile(ast.Module(body=[node], type_ignores=[]), file, 'exec'), namespace)
    return namespace[name]


@contextmanager
def _fixture(function):
    generator = function()
    try:
        yield next(generator)
    finally:
        generator.close()


def _prior(owner, name, state):
    previous = None if state == 'negative' else ModuleType(name)
    owner.setitem(sys.modules, name, previous)
    if state == 'missing':
        del sys.modules[name]
        return _MISSING
    return previous


def _assert_prior(expected):
    for name, value in expected.items():
        if value is _MISSING:
            assert name not in sys.modules, name
        else:
            assert sys.modules[name] is value, name


def _window(case, table):
    namespace = dict(sys=SimpleNamespace(modules=table), fresh_module_tree=registry.fresh_module_tree)
    function = _function(case['file'], case['function'], namespace, window=True)
    return contextmanager(function)()


def _layout(state, parent_state):
    parent = ModuleType('core')
    original = ModuleType('core.json')
    table = {'core': parent, 'core.json.cache': None, 'core.json.utils': ModuleType('core.json.utils')}
    if state != 'missing':
        table['core.json'] = None if state == 'negative' else original
    raw = {'missing': _MISSING, 'negative': None, 'borrowed': object(), 'matching': table.get('core.json', original)}[parent_state]
    if raw is not _MISSING:
        parent.json = raw
    return table, parent, raw


def _assert_layout(table, saved, parent, raw):
    assert {key: value for key, value in table.items() if key.startswith('core.json')} == saved
    if raw is _MISSING:
        assert 'json' not in vars(parent)
    else:
        assert vars(parent)['json'] is raw


@pytest.mark.parametrize('case', _SITES['windows'], ids=lambda row: row['file'])
@pytest.mark.parametrize('state', ['missing', 'negative', 'borrowed'])
@pytest.mark.parametrize('parent_state', ['missing', 'negative', 'borrowed', 'matching'])
@pytest.mark.parametrize('outcome', ['normal', 'error', 'interrupt'])
def test_native_import_windows_restore_independent_parent_binding(case, state, parent_state, outcome):
    table, parent, raw = _layout(state, parent_state)
    saved = {key: value for key, value in table.items() if key.startswith('core.json')}
    other = ModuleType('unrelated_import')
    failure = RuntimeError('consumer failed') if outcome == 'error' else KeyboardInterrupt('consumer interrupted')
    with pytest.MonkeyPatch.context() as owner:
        patch_module_attribute(owner, registry, 'sys', 'modules', table)
        def consume():
            with _window(case, table):
                assert not any(key.startswith('core.json') for key in table)
                table['core.json'] = parent.json = ModuleType('core.json')
                table['core.json.fresh'] = ModuleType('core.json.fresh')
                table['unrelated_import'] = other
                if outcome != 'normal':
                    raise failure
        if outcome == 'normal':
            consume()
        else:
            with pytest.raises(type(failure)) as caught:
                consume()
            assert caught.value is failure
    _assert_layout(table, saved, parent, raw)
    assert table['unrelated_import'] is other


@pytest.mark.parametrize('case', _SITES['windows'], ids=lambda row: row['file'])
@pytest.mark.parametrize('position', [0, 1, 2])
@pytest.mark.parametrize('failure_type', [RuntimeError, KeyboardInterrupt])
def test_native_purge_registers_restoration_before_first_removal(case, position, failure_type):
    initial, parent, raw = _layout('borrowed', 'borrowed')
    selected = list(key for key in initial if key.startswith('core.json'))
    failure = failure_type('purge interrupted')
    fired = []
    class Table(dict):
        def fail(self, name):
            if name == selected[position] and not fired:
                fired.append(name)
                raise failure
        def pop(self, name, default=None):
            value = super().pop(name, default)
            self.fail(name)
            return value
        def __delitem__(self, name):
            super().__delitem__(name)
            self.fail(name)
    table = Table(initial)
    with pytest.MonkeyPatch.context() as owner:
        patch_module_attribute(owner, registry, 'sys', 'modules', table)
        with pytest.raises(failure_type) as caught:
            with _window(case, table):
                pytest.fail('interrupted purge reached consumer')
        assert caught.value is failure
    assert fired
    _assert_layout(table, {key: initial[key] for key in selected}, parent, raw)


@pytest.mark.parametrize('position', [0, 1, 2])
@pytest.mark.parametrize('failure_type', [RuntimeError, KeyboardInterrupt])
def test_tree_restoration_finishes_after_one_setter_fails(position, failure_type):
    initial, parent, raw = _layout('borrowed', 'borrowed')
    selected = [key for key in initial if key.startswith('core.json')]
    failure = failure_type('restoration interrupted')
    fired = []
    class Table(dict):
        def __setitem__(self, name, value):
            super().__setitem__(name, value)
            if name == selected[position] and value is initial[name] and not fired:
                fired.append(name)
                raise failure
    table = Table(initial)
    with pytest.MonkeyPatch.context() as owner:
        patch_module_attribute(owner, registry, 'sys', 'modules', table)
        with pytest.raises(failure_type) as caught:
            with registry.fresh_module_tree('core.json'):
                table['core.json'] = parent.json = ModuleType('core.json')
                table['core.json.fresh'] = ModuleType('core.json.fresh')
        assert caught.value is failure
    assert fired
    _assert_layout(table, {key: initial[key] for key in selected}, parent, raw)


@pytest.mark.parametrize('state', ['missing', 'negative', 'borrowed'])
@pytest.mark.parametrize('outcome', ['normal', 'error', 'interrupt'])
def test_nested_tree_windows_restore_the_outer_import(state, outcome):
    table, parent, raw = _layout(state, 'borrowed')
    initial = dict(table)
    failure = RuntimeError('nested failed') if outcome == 'error' else KeyboardInterrupt('nested interrupted')
    with pytest.MonkeyPatch.context() as owner:
        patch_module_attribute(owner, registry, 'sys', 'modules', table)
        with registry.fresh_module_tree('core.json'):
            outer = table['core.json'] = parent.json = ModuleType('core.json')
            def consume():
                with registry.fresh_module_tree('core.json'):
                    table['core.json'] = parent.json = ModuleType('core.json')
                    if outcome != 'normal':
                        raise failure
            if outcome == 'normal':
                consume()
            else:
                with pytest.raises(type(failure)):
                    consume()
            assert table['core.json'] is outer and parent.json is outer
    assert table == initial
    assert parent.json is raw


@pytest.mark.parametrize('state', ['missing', 'negative', 'borrowed'])
@pytest.mark.parametrize('outcome', ['normal', 'setup_error', 'setup_interrupt', 'body_error', 'body_interrupt'])
def test_dispatcher_fixture_restores_negative_cache_and_partial_import(state, outcome):
    table = {} if state == 'missing' else {'raptor': None if state == 'negative' else ModuleType('raptor')}
    initial = dict(table)
    failure = KeyboardInterrupt('interrupted') if outcome.endswith('interrupt') else RuntimeError('failed')
    loaded = ModuleType('raptor')
    seen = []
    def importing(name):
        assert name == 'raptor' and name not in table
        seen.append(name)
        table[name] = loaded
        if outcome.startswith('setup_'):
            raise failure
        return loaded
    namespace = dict(sys=SimpleNamespace(modules=table), importlib=SimpleNamespace(import_module=importing),
                     module_registry_scope=registry.module_registry_scope)
    function = _function('core/llm/tests/test_dispatcher_startup_loud.py', 'fresh_raptor_module', namespace)
    with pytest.MonkeyPatch.context() as owner:
        patch_module_attribute(owner, registry, 'sys', 'modules', table)
        def consume():
            with _fixture(function) as module:
                assert module is loaded
                if outcome.startswith('body_'):
                    raise failure
        if outcome == 'normal':
            consume()
        else:
            with pytest.raises(type(failure)) as caught:
                consume()
            assert caught.value is failure
    assert seen == ['raptor']
    assert table == initial


def _script(tmp_path, monkeypatch, outcome):
    hook = ModuleType('_owned_loader_' + uuid4().hex)
    hook.seen = []
    hook.failure = RuntimeError('import failed') if outcome == 'error' else KeyboardInterrupt('import interrupted')
    monkeypatch.setitem(sys.modules, hook.__name__, hook)
    script = tmp_path / 'helper.py'
    script.write_text('from __future__ import annotations\nfrom dataclasses import dataclass\nimport sys\n'
                      f'control = sys.modules[{hook.__name__!r}]\ncontrol.seen.append(__name__)\n'
                      '@dataclass\nclass Record:\n    next: Record | None = None\n'
                      + ('raise control.failure\n' if outcome != 'normal' else ''))
    return script, hook


@pytest.mark.parametrize('alias', ['compiler_scan_golden_test', 'scanner_golden_test'])
@pytest.mark.parametrize('state', ['missing', 'negative', 'borrowed'])
@pytest.mark.parametrize('outcome', ['normal', 'error', 'interrupt'])
def test_golden_loader_scope_owns_dataclass_alias_until_consumed(alias, state, outcome, tmp_path, monkeypatch):
    names = ['compiler_scan_golden_test', 'scanner_golden_test']
    expected = {name: _prior(monkeypatch, name, state) for name in names}
    script, hook = _script(tmp_path, monkeypatch, outcome)
    file = 'packages/static-analysis/tests/test_sarif_golden.py'
    namespace = dict(sys=sys, importlib=importlib, patch=patch, _PKG_DIR=tmp_path,
                     fresh_module_tree=registry.fresh_module_tree)
    load = _function(file, '_load', namespace)
    has_scope = any(isinstance(n, ast.FunctionDef) and n.name == '_golden_module_scope' for n in ast.walk(_tree(file)))
    scope = _fixture(_function(file, '_golden_module_scope', namespace)) if has_scope else nullcontext()
    def consume():
        with scope:
            module = load(alias, script.name)
            assert hook.seen == [alias], 'golden loader reused a borrowed module'
            assert get_type_hints(module.Record)['next'] == module.Record | None
    if outcome == 'normal':
        consume()
    else:
        with pytest.raises(type(hook.failure)) as caught:
            consume()
        assert caught.value is hook.failure
    _assert_prior(expected)


@pytest.mark.parametrize('state', ['missing', 'negative', 'borrowed'])
@pytest.mark.parametrize('outcome', ['normal', 'error', 'interrupt'])
def test_census_loader_preserves_existing_alias(state, outcome, tmp_path, monkeypatch):
    alias = '_redos_idiom_census_for_sca'
    expected = {alias: _prior(monkeypatch, alias, state)}
    script, hook = _script(tmp_path, monkeypatch, outcome)
    namespace = dict(importlib=importlib, sys=sys, patch=patch, _CENSUS_PATH=script,
                     module_registry_scope=registry.module_registry_scope)
    function = _function('packages/sca/supply_chain/tests/test_pattern_data_census.py', '_census', namespace)
    if outcome == 'normal':
        assert function().Record().next is None
    else:
        with pytest.raises(type(hook.failure)) as caught:
            function()
        assert caught.value is hook.failure
    assert hook.seen == [alias]
    _assert_prior(expected)


@pytest.mark.parametrize('state', ['negative', 'empty', 'borrowed'])
@pytest.mark.parametrize('failure_at', [None, 'exfil_error', 'exfil_interrupt', 'binary_error', 'binary_interrupt'])
def test_pattern_census_restores_both_cache_objects(state, failure_at):
    exfil, binary = ModuleType('exfil'), ModuleType('binary')
    exfil._RULES_CACHE = None if state == 'negative' else [] if state == 'empty' else [object()]
    binary._ALLOWLIST = None if state == 'negative' else {} if state == 'empty' else {'borrowed': object()}
    originals = exfil._RULES_CACHE, binary._ALLOWLIST
    seen = []
    failure = KeyboardInterrupt('loader interrupted') if failure_at and failure_at.endswith('interrupt') else RuntimeError('loader failed')
    def rules():
        assert exfil._RULES_CACHE is None
        seen.append('exfil')
        exfil._RULES_CACHE = [SimpleNamespace(category='owned', pattern=re.compile('(?m)a$'))]
        if failure_at and failure_at.startswith('exfil_'):
            raise failure
        return exfil._RULES_CACHE
    def allowlist():
        assert binary._ALLOWLIST is None
        seen.append('binary')
        binary._ALLOWLIST = {'name_suffix_opt_in': {'patterns': ['(?m)a$']}}
        if failure_at and failure_at.startswith('binary_'):
            raise failure
        return binary._ALLOWLIST
    exfil._load_rules, binary._load_allowlist = rules, allowlist
    namespace = dict(_census=lambda: SimpleNamespace(_compiled_is_member=lambda pattern: bool(pattern.flags & re.MULTILINE)),
                     _exfil=exfil, _bip=binary, re=re, isolated_module_state=isolated_module_state)
    function = _function('packages/sca/supply_chain/tests/test_pattern_data_census.py', '_sca_data_file_members', namespace)
    if failure_at is None:
        assert function() == [('exfil:owned', '(?m)a$'), ('binary-name-suffix', '(?m)a$')]
    else:
        with pytest.raises(type(failure)) as caught:
            function()
        assert caught.value is failure
    assert seen == (['exfil'] if failure_at and failure_at.startswith('exfil_') else ['exfil', 'binary'])
    assert exfil._RULES_CACHE is originals[0] and binary._ALLOWLIST is originals[1]


@pytest.mark.parametrize('case', _SITES['probes'], ids=lambda row: row['function'])
@pytest.mark.parametrize('state', ['missing', 'negative', 'borrowed'])
@pytest.mark.parametrize('outcome', ['normal', 'error', 'interrupt'])
def test_real_protected_path_probe_restores_module_entries(case, state, outcome, tmp_path, monkeypatch):
    from core.security import python_imports
    from core.startup import install_guard

    root = case['root']
    expected = {name: _prior(monkeypatch, name, state) for name in [root, root + '.safe', root + '.unsafe']}
    seen = []
    failure = RuntimeError('import consumer failed') if outcome == 'error' else KeyboardInterrupt('import consumer interrupted')
    def importing_module(name):
        module = importlib.import_module(name)
        if name == root or name.startswith(root + '.'):
            assert getattr(module, '__file__', None), 'probe reused a borrowed module'
            seen.append(name)
            if outcome != 'normal':
                raise failure
        return module
    def importing(name, *args, **kwargs):
        return SimpleNamespace(import_module=importing_module) if name == 'importlib' else builtins.__import__(name, *args, **kwargs)
    namespace = dict(python_imports=python_imports, install_guard=install_guard, sys=sys, os=os, pytest=pytest,
                     fresh_module_tree=registry.fresh_module_tree, __builtins__={**vars(builtins), '__import__': importing})
    function = _function('core/security/tests/test_python_imports.py', case['function'], namespace)
    with pytest.MonkeyPatch.context() as owner:
        if case['function'] != 'test_writable_shadow_module_is_not_executed':
            layout = _function('core/security/tests/test_python_imports.py', 'import_layout', namespace)(tmp_path, owner)
            call = lambda: function(layout)
        else:
            call = lambda: function(tmp_path, owner)
        if outcome == 'normal':
            call()
        else:
            with pytest.raises(type(failure)) as caught:
                call()
            assert caught.value is failure
    assert seen
    _assert_prior(expected)


@pytest.mark.parametrize('state', ['empty', 'negative', 'borrowed'])
@pytest.mark.parametrize('error', ['ImportError', 'RuntimeError'])
def test_failed_frida_probe_preserves_importer_cache(state, error, tmp_path, monkeypatch):
    from packages.frida import sandboxed
    importlib.import_module('packages.frida.runner')
    original = {} if state == 'empty' else {'/owned/foreign-importer': None if state == 'negative' else object()}
    monkeypatch.setattr(sys, 'path_importer_cache', original)
    before = dict(original)
    namespace = dict(sys=sys, pytest=pytest, sandboxed=sandboxed)
    function = _function('packages/frida/tests/test_probe_import_hygiene.py', 'test_runner_cleans_failed_binding_path', namespace)
    with pytest.MonkeyPatch.context() as owner:
        function(tmp_path, owner, error)
    assert sys.path_importer_cache is original and original == before


@pytest.mark.parametrize('state', ['missing', 'negative', 'borrowed'])
def test_contention_test_does_not_delete_an_unpublished_alias(state, monkeypatch):
    alias = 'raptor_sca_run_contention'
    expected = {alias: _prior(monkeypatch, alias, state)}
    namespace = dict(sys=sys, pytest=pytest, Path=Path, TemporaryDirectory=TemporaryDirectory, WRAPPER=_ROOT/'libexec/raptor-sca-run')
    function = _function('packages/sca/tests/test_raptor_sca_run.py', 'test_contention_prints_error_line', namespace)
    function(unittest.TestCase())
    _assert_prior(expected)


@pytest.mark.slow
@pytest.mark.parametrize('method', _SITES['cli_methods'])
def test_native_sca_cli_matrix_owns_stale_launch_state(method, monkeypatch):
    native = importlib.import_module('packages.sca.tests.test_raptor_sca_run')
    namespace = dict(vars(native))
    owned_run = _function('packages/sca/tests/test_raptor_sca_run.py', '_run', namespace)
    monkeypatch.setattr(native, '_run', owned_run)
    monkeypatch.setenv('_RAPTOR_SCRATCH_AUTH', 'invalid-inherited-authorisation')
    monkeypatch.setenv('RAPTOR_SESSION_PID', '999999')
    monkeypatch.setenv('RAPTOR_SESSION_TOKEN', 'invalid-inherited-session')
    before = dict(os.environ)
    instance = native.RaptorScaRunWrapperTests(method)
    instance.setUp()
    try:
        getattr(instance, method)()
    finally:
        instance.tearDown()
    assert dict(os.environ) == before


def test_sca_direct_script_bootstraps_before_running_cli_cases(monkeypatch):
    file = 'packages/sca/tests/test_raptor_sca_run.py'
    guard = next(n for n in _tree(file).body if isinstance(n, ast.If) and ast.unparse(n.test) == "__name__ == '__main__'")
    seen = []
    def main():
        assert str(_ROOT) in sys.path
        seen.append(True)
    monkeypatch.setattr(sys, 'path', [entry for entry in sys.path if Path(entry or '.').resolve() != _ROOT])
    exec(compile(ast.Module(body=[guard], type_ignores=[]), file, 'exec'),
         dict(__name__='__main__', sys=sys, REPO_ROOT=_ROOT, unittest=SimpleNamespace(main=main)))
    assert seen == [True]

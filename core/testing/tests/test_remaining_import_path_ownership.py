"""Import setup, collection probes and coverage bodies retain caller paths."""

import ast
import builtins
from contextlib import contextmanager
import importlib.machinery
import importlib.util
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

import pytest

from core.testing.module_registry import module_registry_scope
from core.testing.module_state import isolated_module_state


ROOT = Path(__file__).resolve().parents[3]
CLASS_HELPERS = [
    ('packages/autonomous/tests/test_phase_timeout.py', 'RunCommandStreamingTimeoutTests',
     '_import_helper', 'raptor_agentic', 'run_command_streaming'),
    ('packages/fuzzing/tests/test_campaign_execs_record.py', 'CampaignExecsTests',
     '_campaign_execs', 'raptor_fuzzing', '_campaign_execs'),
]


def _function(file, name, namespace, owner=None):
    scope = ast.parse((ROOT / file).read_text())
    if owner is not None:
        scope = next(n for n in scope.body if isinstance(n, ast.ClassDef) and n.name == owner)
    node = next(n for n in scope.body if isinstance(n, ast.FunctionDef) and n.name == name)
    node.decorator_list = []
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(ROOT / file), 'exec'), namespace)
    return namespace[name]


def _path(kind):
    original = [p for p in sys.path if p not in ('', str(ROOT))]
    if kind == 'tuple':
        return tuple(original)
    if kind == 'duplicate':
        return [str(ROOT), *original, str(ROOT)]
    return original


@pytest.mark.parametrize('file,owner,name,target,attribute', CLASS_HELPERS,
                         ids=['streaming', 'campaign'])
@pytest.mark.parametrize('kind', ['missing', 'duplicate', 'tuple'])
@pytest.mark.parametrize('mode', ['normal', 'warm', 'import_error', 'import_interrupt',
                                 'publication_error', 'publication_interrupt', 'negative_cache'])
def test_class_import_helper_retains_path(file, owner, name, target, attribute, kind, mode, monkeypatch):
    borrowed = _path(kind)
    contents = tuple(borrowed)
    reached, published = [], []
    failure = KeyboardInterrupt('owned interruption') if mode.endswith('interrupt') else RuntimeError('owned failure')
    imported = ModuleType(target)

    def resolved():
        return 'owned callable'

    setattr(imported, attribute, resolved)

    @contextmanager
    def object_scope(obj, field, value):
        with patch.object(obj, field, value):
            published.append(field)
            assert obj is sys and field == 'path' and sys.path is not borrowed
            if mode.startswith('publication_'):
                raise failure
            yield

    def importing(module, globals=None, locals=None, fromlist=(), level=0):
        if module == 'unittest.mock':
            return SimpleNamespace(patch=SimpleNamespace(object=object_scope))
        if module == target:
            reached.append(module)
            assert sys.path is not borrowed and str(ROOT) in sys.path
            assert tuple(borrowed) == contents
            sys.path.append('owned import effect')
            if mode.startswith('import_'):
                raise failure
            if mode == 'negative_cache':
                return builtins.__import__(module, globals, locals, fromlist, level)
            return imported
        return builtins.__import__(module, globals, locals, fromlist, level)

    namespace = {'sys': sys, 'REPO_ROOT': ROOT,
                 '__builtins__': {**vars(builtins), '__import__': importing}}
    function = _function(file, name, namespace, owner)
    with module_registry_scope(target) as modules, monkeypatch.context() as body:
        if mode in ('warm', 'negative_cache'):
            modules[target] = imported if mode == 'warm' else None
        else:
            modules.pop(target, None)
        body.setattr(sys, 'path', borrowed)
        if mode in ('normal', 'warm'):
            assert function(unittest.TestCase()) is resolved
        elif mode == 'negative_cache':
            with pytest.raises(ModuleNotFoundError, match='None in sys.modules'):
                function(unittest.TestCase())
        else:
            with pytest.raises(type(failure)) as caught:
                function(unittest.TestCase())
            assert caught.value is failure
        if mode == 'warm':
            assert modules[target] is imported
        if mode == 'negative_cache':
            assert modules[target] is None
        assert published == ['path']
        assert bool(reached) is (not mode.startswith('publication_'))
        assert sys.path is borrowed and tuple(borrowed) == contents


@pytest.mark.parametrize('kind', ['missing', 'duplicate', 'tuple'])
@pytest.mark.parametrize('mode', ['normal', 'discover_error', 'discover_interrupt',
                                 'create_error', 'create_interrupt', 'exec_error',
                                 'exec_interrupt', 'publication_error', 'publication_interrupt'])
def test_module_loader_scope_covers_setup_and_execution(kind, mode, monkeypatch):
    file = 'packages/llm_analysis/tests/test_agentic_dv_reporting.py'
    borrowed = _path(kind)
    contents = tuple(borrowed)
    reached, published = [], []
    failure = KeyboardInterrupt('owned loader interruption') if mode.endswith('interrupt') else RuntimeError('owned loader failure')

    def step(phase):
        reached.append(phase)
        assert sys.path is not borrowed and str(ROOT) in sys.path
        assert tuple(borrowed) == contents
        sys.path.append('owned ' + phase)
        if mode.startswith(phase + '_'):
            raise failure

    class Loader:
        def create_module(self, spec):
            step('create')
            return None

        def exec_module(self, module):
            step('exec')
            module.executed = True

    def specification(name, path):
        step('discover')
        assert path == ROOT / 'raptor_agentic.py'
        return importlib.machinery.ModuleSpec(name, Loader(), origin=str(path))

    @contextmanager
    def object_scope(obj, field, value):
        with patch.object(obj, field, value):
            published.append(field)
            assert obj is sys and field == 'path' and sys.path is not borrowed
            if mode.startswith('publication_'):
                raise failure
            yield

    namespace = {'__file__': str(ROOT / file), 'Path': Path, 'sys': sys,
                 'patch': SimpleNamespace(object=object_scope),
                 'importlib': SimpleNamespace(util=SimpleNamespace(
                     spec_from_file_location=specification,
                     module_from_spec=importlib.util.module_from_spec))}
    function = _function(file, '_load_agentic_module', namespace)
    with monkeypatch.context() as body:
        body.setattr(sys, 'path', borrowed)
        if mode == 'normal':
            module = function()
            assert isinstance(module, ModuleType) and module.executed
        else:
            with pytest.raises(type(failure)) as caught:
                function()
            assert caught.value is failure
        assert published == ['path']
        expected = [] if mode.startswith('publication_') else ['discover']
        if not mode.startswith(('publication_', 'discover_')):
            expected.append('create')
            if not mode.startswith('create_'):
                expected.append('exec')
        assert reached == expected
        assert sys.path is borrowed and tuple(borrowed) == contents


def _probe_cases():
    for kind in ('missing', 'duplicate', 'tuple'):
        yield pytest.param(kind, 'darwin', 'normal', False, id=f'{kind}-darwin')
        for mode, available in [('normal', False), ('normal', True),
                                ('import_error', False), ('import_interrupt', False),
                                ('probe_error', False), ('probe_interrupt', False)]:
            yield pytest.param(kind, 'linux', mode, available,
                               id=f'{kind}-{mode}-{available}')


@pytest.mark.parametrize('kind,platform,mode,available', list(_probe_cases()))
def test_collection_probe_retains_path_and_dispatch(kind, platform, mode, available):
    file = 'packages/zkpox/tests/test_libexec_raptor_zkpox.py'
    borrowed = _path(kind)
    contents = tuple(borrowed)
    private_sys = ModuleType('owned_probe_sys')
    private_sys.platform, private_sys.path = platform, borrowed
    reached, calls = [], []
    failure = KeyboardInterrupt('owned probe interruption') if mode.endswith('interrupt') else RuntimeError('owned probe failure')

    def probe():
        calls.append(True)
        if mode.startswith('probe_'):
            raise failure
        return available

    def importing(name, globals=None, locals=None, fromlist=(), level=0):
        if name == 'core.sandbox.probes':
            reached.append(True)
            assert private_sys.path is borrowed and tuple(borrowed) == contents
            if mode.startswith('import_'):
                raise failure
            return SimpleNamespace(check_mount_available=probe)
        return builtins.__import__(name, globals, locals, fromlist, level)

    namespace = {'sys': private_sys, 'REPO': ROOT,
                 '__builtins__': {**vars(builtins), '__import__': importing}}
    function = _function(file, '_mount_ns_usable', namespace)
    if mode == 'normal':
        assert function() is (available if platform == 'linux' else False)
    else:
        with pytest.raises(type(failure)) as caught:
            function()
        assert caught.value is failure
    assert bool(reached) is (platform == 'linux')
    assert bool(calls) is (platform == 'linux' and not mode.startswith('import_'))
    assert private_sys.path is borrowed and tuple(borrowed) == contents


@pytest.fixture(scope='module')
def summary_native():
    name = '_owned_summary_path_tests'
    file = ROOT / 'core/coverage/tests/test_summary_map_grade.py'
    with module_registry_scope(name) as modules:
        spec = importlib.util.spec_from_file_location(name, file)
        module = importlib.util.module_from_spec(spec)
        modules[name] = module
        spec.loader.exec_module(module)
        yield module


@pytest.mark.slow
@pytest.mark.parametrize('name', ['test_map_grade_marked_function_stays_in_review_gap',
                                 'test_review_mark_still_deduplicates_gap'])
@pytest.mark.parametrize('kind', ['missing', 'duplicate', 'tuple'])
@pytest.mark.parametrize('mode', ['normal', 'import_error', 'import_interrupt',
                                 'body_error', 'body_interrupt'])
def test_coverage_body_retains_path(summary_native, name, kind, mode, tmp_path, monkeypatch):
    from core.coverage.tests import summary_cli_support
    import core.audit.gaps as gaps

    borrowed = _path(kind)
    contents = tuple(borrowed)
    reached, computed = [], []
    failure = KeyboardInterrupt('owned coverage interruption') if mode.endswith('interrupt') else RuntimeError('owned coverage failure')

    def compute(*args, **kwargs):
        result = gaps.compute_gaps(*args, **kwargs)
        expected = {'f1', 'f2'} if name.startswith('test_map_grade') else {'f2'}
        assert {row['name'] for row in result} == expected
        computed.append(True)
        if mode.startswith('body_'):
            raise failure
        return result

    def importing(module, globals=None, locals=None, fromlist=(), level=0):
        if module == 'core.audit.gaps':
            reached.append(True)
            assert sys.path is not borrowed and tuple(borrowed) == contents
            if mode.startswith('import_'):
                raise failure
            view = ModuleType(module)
            vars(view).update(vars(gaps))
            view.compute_gaps = compute
            return view
        return builtins.__import__(module, globals, locals, fromlist, level)

    namespace = {**vars(summary_native),
                 '__builtins__': {**vars(builtins), '__import__': importing}}
    function = _function('core/coverage/tests/test_summary_map_grade.py', name, namespace)
    # Parent writers, operator calls and CLI children share this owned key.
    with isolated_module_state(summary_cli_support, {'_cli_module': None}), monkeypatch.context() as body:
        body.setenv('XDG_DATA_HOME', str(tmp_path / 'signing'))
        # Own CLI setup before varying the coverage body's import path.
        summary_cli_support._load_cli_module()
        body.setattr(sys, 'path', borrowed)
        if mode == 'normal':
            function(tmp_path)
        else:
            with pytest.raises(type(failure)) as caught:
                function(tmp_path)
            assert caught.value is failure
        assert reached == [True]
        assert bool(computed) is (not mode.startswith('import_'))
        assert sys.path is borrowed and tuple(borrowed) == contents

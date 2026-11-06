"""Egress fixture owners preserve borrowed module state and env presence."""

import ast
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path
import os
import threading
from types import FunctionType, ModuleType

import pytest

import core.llm
from core.llm import egress as real_egress
from core.testing import llm_env


ROOT = Path(__file__).resolve().parents[3]


@lru_cache(maxsize=1)
def _root_fixture():
    node = next(n for n in ast.parse((ROOT / 'conftest.py').read_text()).body
                if isinstance(n, ast.FunctionDef) and n.name == '_llm_egress_env_hermetic')
    node.decorator_list = []
    namespace = {'pytest': pytest}
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(ROOT / 'conftest.py'), 'exec'), namespace)
    return namespace[node.name]


@pytest.fixture
def view(monkeypatch):
    module = ModuleType(real_egress.__name__)
    vars(module).update(vars(real_egress))
    module._STATE_LOCK = threading.Lock()
    module._reset_for_tests = FunctionType(real_egress._reset_for_tests.__code__, vars(module))
    monkeypatch.setattr(core.llm, 'egress', module)
    return module


@contextmanager
def owner(kind, *, pin=True, patch_type=pytest.MonkeyPatch):
    if kind == 'root':
        scope = _root_fixture()()
        try:
            next(scope)
            yield
        finally:
            try:
                next(scope)
            except StopIteration:
                pass
            finally:
                scope.close()
    else:
        with patch_type.context() as patch:
            scope = llm_env.reset_llm_egress_state(patch, pin_ollama_host=pin)
            try:
                next(scope)
                yield
            finally:
                try:
                    next(scope)
                except StopIteration:
                    pass
                finally:
                    scope.close()


def _snapshot():
    return {name: (name in os.environ, os.environ.get(name))
            for name in (*llm_env.PROXY_ENV_VARS, 'OLLAMA_HOST')}


def _finish(mode):
    if mode == 'error':
        raise RuntimeError('owned body failure')
    if mode == 'interrupt':
        raise KeyboardInterrupt


@pytest.mark.parametrize('kind', ['root', 'shared'])
@pytest.mark.parametrize('enabled', [False, True])
@pytest.mark.parametrize('original', ['none', 'empty', 'populated'])
@pytest.mark.parametrize('mode', ['normal', 'undo', 'local_only', 'error', 'interrupt'])
def test_borrowed_flags_and_cache_identity(kind, enabled, original, mode, view):
    borrowed = None if original == 'none' else {} if original == 'empty' else {'HTTPS_PROXY': 'http://caller.invalid:3128'}
    view._enabled, view._original_proxy_env = enabled, borrowed
    expected = None if borrowed is None else dict(borrowed)
    before = _snapshot()
    try:
        with owner(kind):
            assert view._enabled is False
            assert view._original_proxy_env is None
            with pytest.MonkeyPatch.context() as patch:
                patch.setattr(view, '_enabled', True)
                patch.setattr(view, '_original_proxy_env', {'NO_PROXY': 'body'})
                patch.setenv('NO_PROXY', 'body.invalid')
                if mode == 'undo':
                    patch.undo()
                    assert view._enabled is False
                    assert view._original_proxy_env is None
            # The producer writes after body-patch cleanup, so that stack
            # cannot accidentally repair the fixture owner's direct writes.
            with view._STATE_LOCK:
                view._enabled = mode != 'local_only'
                view._original_proxy_env = {'NO_PROXY': 'owned'}
                os.environ['NO_PROXY'] = 'owned.invalid'
            _finish(mode)
    except (RuntimeError, KeyboardInterrupt):
        pass
    assert view._enabled is enabled
    assert view._original_proxy_env is borrowed
    assert borrowed == expected
    assert _snapshot() == before


ENV_CASES = [('root', name) for name in (*llm_env.PROXY_ENV_VARS, 'OLLAMA_HOST')] + [
    ('shared', name) for name in (*llm_env.PROXY_ENV_VARS, 'OLLAMA_HOST')]


@pytest.mark.parametrize('kind,name', ENV_CASES, ids=[kind + '-' + name for kind, name in ENV_CASES])
@pytest.mark.parametrize('initial', [None, '', 'http://caller.invalid:3128'])
@pytest.mark.parametrize('mode', ['normal', 'undo', 'error', 'interrupt'])
def test_direct_env_writes_restore_presence(kind, name, initial, mode, view, monkeypatch):
    if initial is None:
        monkeypatch.delenv(name, raising=False)
    else:
        monkeypatch.setenv(name, initial)
    view._enabled, view._original_proxy_env = False, None
    before = _snapshot()
    try:
        with owner(kind):
            with pytest.MonkeyPatch.context() as patch:
                patch.setenv(name, 'body')
                if mode == 'undo':
                    patch.undo()
            os.environ[name] = 'direct-write'
            view._enabled = False
            _finish(mode)
    except (RuntimeError, KeyboardInterrupt):
        pass
    assert _snapshot() == before


@pytest.mark.parametrize('name', [*llm_env.PROXY_ENV_VARS, 'OLLAMA_HOST'])
@pytest.mark.parametrize('error', [RuntimeError, KeyboardInterrupt])
def test_partial_env_publication_restores_everything(name, error, view):
    borrowed = {'HTTPS_PROXY': 'caller'}
    view._enabled, view._original_proxy_env = True, borrowed
    before = _snapshot()
    class InterruptedPatch(pytest.MonkeyPatch):
        armed = True
        def setenv(self, key, value, *args, **kwargs):
            if self.armed and key == name:
                self.armed = False
                # Model a setter that publishes before registering undo.
                os.environ[key] = value
                raise error('after publication')
            super().setenv(key, value, *args, **kwargs)

    with pytest.raises(error):
        with owner('shared', patch_type=InterruptedPatch):
            pass
    assert view._enabled is True
    assert view._original_proxy_env is borrowed
    assert _snapshot() == before


@pytest.mark.parametrize('kind', ['root', 'shared'])
@pytest.mark.parametrize('field', ['_enabled', '_original_proxy_env'])
@pytest.mark.parametrize('error', [RuntimeError, KeyboardInterrupt])
def test_flag_publication_is_locked_and_unwinds(kind, field, error, view):
    borrowed = {'HTTP_PROXY': 'caller'}
    view._enabled, view._original_proxy_env = True, borrowed
    before = _snapshot()

    class CheckedModule(ModuleType):
        armed = True
        def __setattr__(self, name, value):
            if name in ('_enabled', '_original_proxy_env'):
                assert self._STATE_LOCK.locked(), name
            super().__setattr__(name, value)
            if self.armed and name == field:
                self.armed = False
                raise error('after flag publication')

    view.__class__ = CheckedModule
    try:
        with pytest.raises(error):
            with owner(kind):
                pass
        assert view._enabled is True
        assert view._original_proxy_env is borrowed
        assert _snapshot() == before
    finally:
        view.__class__ = ModuleType


@pytest.mark.parametrize('pin', [False, True])
def test_ollama_pin_is_optional_and_restored(pin, view, monkeypatch):
    monkeypatch.setenv('OLLAMA_HOST', 'http://caller.invalid:11434')
    with owner('shared', pin=pin):
        assert os.environ['OLLAMA_HOST'] == (llm_env.DEFAULT_OLLAMA_HOST if pin else 'http://caller.invalid:11434')
    assert os.environ['OLLAMA_HOST'] == 'http://caller.invalid:11434'


def test_review_loop_scope_preserves_borrowed_state(view):
    import contextlib
    from core.audit import capabilities, orchestrator

    path = ROOT / 'core/audit/tests/test_resume_e2e.py'
    node = next(n for n in ast.parse(path.read_text()).body
                if isinstance(n, ast.FunctionDef) and n.name == '_review_loop_only')
    namespace = {'pytest': pytest, 'contextlib': contextlib, '_HERMETIC_OLLAMA_HOST': None}
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(path), 'exec'), namespace)
    borrowed = {'HTTPS_PROXY': 'http://caller.invalid:3128'}
    view._enabled, view._original_proxy_env = True, borrowed
    before_env = _snapshot()
    before = (orchestrator._run_mechanical_detectors, orchestrator._study_consumer, capabilities.probe_capabilities)
    with namespace['_review_loop_only']():
        assert view._enabled is False
        assert view._original_proxy_env is None
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(view, '_enabled', True)
            patch.setenv('NO_PROXY', 'body')
        view._original_proxy_env = {'NO_PROXY': 'owned'}
        os.environ['NO_PROXY'] = 'owned'
    assert view._enabled is True
    assert view._original_proxy_env is borrowed
    assert _snapshot() == before_env
    assert (orchestrator._run_mechanical_detectors, orchestrator._study_consumer, capabilities.probe_capabilities) == before


def test_module_state_restores_lazy_namespace_absence():
    from core.testing.module_state import isolated_module_state

    module = ModuleType('lazy_fixture')
    borrowed = {'caller': True}
    module.__getattr__ = lambda name: borrowed if name == 'cache' else None
    with isolated_module_state(module, {'cache': {}}):
        assert module.cache == {}
    assert 'cache' not in vars(module)
    assert module.cache is borrowed


def test_module_state_finishes_restore_after_one_undo_error():
    from core.testing.module_state import isolated_module_state

    module = ModuleType('fixture_restore')
    first, second = {'first': 'borrowed'}, {'second': 'borrowed'}
    module.first, module.second = first, second
    armed = True

    class InterruptedRestore(ModuleType):
        def __setattr__(self, name, value):
            nonlocal armed
            super().__setattr__(name, value)
            if armed and name == 'second' and value is second:
                armed = False
                raise RuntimeError('after restoration')

    module.__class__ = InterruptedRestore
    with pytest.raises(RuntimeError, match='after restoration'):
        with isolated_module_state(module, {'first': {}, 'second': {}}):
            assert module.first is not first
            assert module.second is not second
    assert module.first is first
    assert module.second is second


def test_env_restoration_finishes_after_one_callback_error(view, monkeypatch):
    from collections.abc import MutableMapping

    before = _snapshot()
    borrowed = {'HTTPS_PROXY': 'caller'}
    view._enabled, view._original_proxy_env = True, borrowed
    actual = os.environ
    armed = False

    class EnvironmentView(MutableMapping):
        def __getitem__(self, key):
            return actual[key]
        def __iter__(self):
            return iter(actual)
        def __len__(self):
            return len(actual)
        def __setitem__(self, key, value):
            nonlocal armed
            actual[key] = value
            if armed and key == 'NO_PROXY':
                armed = False
                assert view._STATE_LOCK.locked()
                raise RuntimeError('after environment restoration')
        def __delitem__(self, key):
            nonlocal armed
            del actual[key]
            if armed and key == 'NO_PROXY':
                armed = False
                assert view._STATE_LOCK.locked()
                raise RuntimeError('after environment restoration')

    # Make the chosen key present so the fault is independent of host env.
    monkeypatch.setenv('NO_PROXY', 'caller')
    before = _snapshot()
    private = ModuleType('fixture_os')
    vars(private).update(vars(os))
    private.environ = EnvironmentView()
    monkeypatch.setattr(llm_env, 'os', private, raising=False)
    with pytest.raises(RuntimeError, match='after environment restoration'):
        with owner('root'):
            for name in (*llm_env.PROXY_ENV_VARS, 'OLLAMA_HOST'):
                actual[name] = 'owned'
            armed = True
    assert _snapshot() == before
    assert view._enabled is True
    assert view._original_proxy_env is borrowed


def test_normal_module_restore_does_not_publish_twice():
    from core.testing.module_state import isolated_module_state

    module = ModuleType('fixture_publications')
    first, second = object(), object()
    module.first, module.second = first, second
    writes = []

    class ObservedModule(ModuleType):
        def __setattr__(self, name, value):
            writes.append((name, value))
            super().__setattr__(name, value)

    module.__class__ = ObservedModule
    with isolated_module_state(module, {'first': None, 'second': None}):
        assert module.first is None and module.second is None
    assert writes == [('first', None), ('second', None), ('second', second), ('first', first)]


@pytest.mark.parametrize('fail_at', [1, 2], ids=['entry', 'exit'])
@pytest.mark.parametrize('error', [RuntimeError, KeyboardInterrupt])
def test_reset_callback_failure_preserves_caller(fail_at, error, view):
    borrowed = {'HTTPS_PROXY': 'caller'}
    view._enabled, view._original_proxy_env = True, borrowed
    before = _snapshot()
    real_reset = view._reset_for_tests
    calls = 0

    def reset():
        nonlocal calls
        calls += 1
        real_reset()
        if calls == fail_at:
            raise error('after reset')

    view._reset_for_tests = reset
    with pytest.raises(error):
        with owner('shared'):
            view._original_proxy_env = {'NO_PROXY': 'owned'}
            os.environ['NO_PROXY'] = 'owned'
    assert view._enabled is True
    assert view._original_proxy_env is borrowed
    assert _snapshot() == before
    assert not view._STATE_LOCK.locked()


def _detector_namespace(view, route):
    import builtins
    import sys

    source = ROOT / 'conftest.py'
    names = {'_capture_egress_baseline', '_check_egress_leak'}
    nodes = [n for n in ast.parse(source.read_text()).body if isinstance(n, ast.FunctionDef) and n.name in names]
    private_os = ModuleType('fixture_os')
    vars(private_os).update(vars(os))
    route.setdefault('PYTEST_XDIST_WORKER', 'probe')
    private_os.environ = route
    private_sys = ModuleType('fixture_sys')
    vars(private_sys).update(vars(sys))
    private_sys.modules = {'core.llm.egress': view}
    real_import = builtins.__import__

    def local_import(name, *args, **kwargs):
        return private_sys if name == 'sys' else real_import(name, *args, **kwargs)

    namespace = {'os':private_os, 'Path':Path, '_fixture_sys':private_sys, '_egress_leaks':[], '_egress_leak_dir':None,
                 '__builtins__':{**vars(builtins), '__import__':local_import}}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(source), 'exec'), namespace)
    return namespace


def _session_view(request, worker):
    from copy import copy

    session = copy(request.session)
    session.config = copy(request.config)
    session.config.workerinput = {'workerid':'probe'} if worker else None
    session.exitstatus = 0
    return session


@pytest.mark.parametrize('worker', [False, True])
@pytest.mark.parametrize('before_enabled', [False, True])
@pytest.mark.parametrize('after_enabled', [False, True])
@pytest.mark.parametrize('route_kind', ['unchanged', 'new', 'changed', 'removed', 'mixed_case'])
def test_leak_detector_preserves_callers_and_rejects_new_leaks(worker, before_enabled, after_enabled, route_kind, view, request):
    key = 'Http_Proxy' if route_kind == 'mixed_case' else 'HTTP_PROXY'
    route = {} if route_kind == 'new' else {key:'http://127.0.0.1:9001'}
    view._enabled = before_enabled
    namespace = _detector_namespace(view, route)
    session = _session_view(request, worker)
    capture = namespace.get('_capture_egress_baseline')
    if capture is not None:
        capture(session)
    view._enabled = after_enabled
    if route_kind in ('new', 'changed'):
        route[key] = 'http://127.0.0.1:9002'
    elif route_kind == 'removed':
        route.clear()
    namespace['_check_egress_leak'](session)
    expected = (after_enabled and not before_enabled) or route_kind in ('new', 'changed')
    assert (session.exitstatus == 1) is expected
    assert bool(namespace['_egress_leaks']) is expected


def test_worker_leak_markers_still_fail_controller(view, request, tmp_path):
    view._enabled = False
    route = {}
    namespace = _detector_namespace(view, route)
    worker = _session_view(request, True)
    capture = namespace.get('_capture_egress_baseline')
    if capture is not None:
        capture(worker)
    namespace['_egress_leak_dir'] = str(tmp_path)
    route['HTTP_PROXY'] = 'http://127.0.0.1:9002'
    namespace['_check_egress_leak'](worker)
    assert worker.exitstatus == 1
    assert list(tmp_path.glob('*.leak'))
    controller_namespace = _detector_namespace(view, {})
    controller_namespace['_egress_leak_dir'] = str(tmp_path)
    controller = _session_view(request, False)
    capture = controller_namespace.get('_capture_egress_baseline')
    if capture is not None:
        capture(controller)
    controller_namespace['_check_egress_leak'](controller)
    assert controller.exitstatus == 1
    assert controller_namespace['_egress_leaks']


@pytest.mark.parametrize('enabled', [False, True])
def test_detector_handles_module_loaded_after_session_start(enabled, view, request):
    namespace = _detector_namespace(view, {})
    namespace['_fixture_sys'].modules.clear()
    session = _session_view(request, False)
    capture = namespace.get('_capture_egress_baseline')
    if capture is not None:
        capture(session)
    assert not namespace['_fixture_sys'].modules
    namespace['_fixture_sys'].modules['core.llm.egress'] = view
    view._enabled = enabled
    namespace['_check_egress_leak'](session)
    assert (session.exitstatus == 1) is enabled

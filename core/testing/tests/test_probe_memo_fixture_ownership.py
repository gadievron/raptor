"""Probe fixtures preserve warm caches, runtime values and thread-local state."""
import ast
import builtins
from collections import OrderedDict
from contextlib import contextmanager
import copy
import functools
import importlib
import json
from pathlib import Path
import threading
from types import FunctionType, ModuleType, SimpleNamespace
from unittest.mock import MagicMock

import pytest
from core.testing.module_state import isolated_module_state

_ROOT = Path(__file__).resolve().parents[3]
_SITES = [
    ('model', 'core/concepts/tests/test_audit_bridge.py', '_owned_model_memos', ('cold', 'warm'), 2),
    ('control', 'core/audit/tests/test_sweep.py', '_owned_negative_control_cache', ('cold', 'warm'), 1),
    ('sanwit', 'core/audit/tests/test_sanwit_channel.py', '_reset_runtime_cache', ('cold', 'native', 'unavailable'), 2),
    ('browser', 'packages/web/tests/test_browser_sandbox_policy.py', '_owned_nested_probe_state',
     ('cold_missing', 'warm_missing', 'cold_false', 'warm_false', 'cold_true', 'warm_true'), 2),
]
_PHP = 'function owned($x) { system(escapeshellcmd($x)); }'


class _Lock:
    def __init__(self):
        self.lock = threading.Lock()
        self.held = False
        self.acquisitions = 0

    def __enter__(self):
        self.lock.acquire()
        self.held = True
        self.acquisitions += 1

    def __exit__(self, *exc):
        self.held = False
        self.lock.release()


def _view(name):
    real = importlib.import_module(name)
    owner = ModuleType(name)
    vars(owner).update(vars(real))
    return owner


def _clone(function, owner):
    clone = FunctionType(function.__code__, vars(owner), argdefs=function.__defaults__)
    clone.__kwdefaults__ = function.__kwdefaults__
    return clone


def _lru(owner, name):
    original = getattr(owner, name)
    private = functools.lru_cache(**original.cache_parameters())(_clone(original.__wrapped__, owner))
    setattr(owner, name, private)
    return private


def _prepare(kind, state, tmp_path):
    modules = {}
    if kind == 'model':
        owner = _view('core.concepts.audit_bridge')
        modules['audit_bridge'] = owner
        owner._slice_memo_lock = _Lock()
        owner._slice_memos = OrderedDict()
        owner._slice_memo_for = _clone(owner._slice_memo_for, owner)
        _lru(owner, '_load_cached')
        (tmp_path / 'domain-model.json').write_text(json.dumps({'concepts': [{'id': 'owned'}]}))
        slots = [(owner, '_load_cached', owner._slice_memo_lock), (owner, '_slice_memos', owner._slice_memo_lock)]
        if state == 'warm':
            for _ in range(3):
                _consume(kind, modules, tmp_path)
    elif kind == 'control':
        owner = _view('core.audit.sweep')
        modules['sweep'] = owner
        owner._negative_control_cache = {('owned', 'c', '.c'): True} if state == 'warm' else {}
        slots = [(owner, '_negative_control_cache', None)]
    elif kind == 'sanwit':
        execute, owner = _view('core.audit.sanwit._execute'), _view('core.audit.sanwit')
        modules.update(sanwit=owner, sanwit_execute=execute)
        execute._RESOLVE_LOCK = _Lock()
        execute._RESOLVED = (execute.PhpRuntime(tier='native', version='8.3.0', php_path='/owned/php')
                             if state == 'native' else execute.RuntimeUnavailable('owned absent')
                             if state == 'unavailable' else None)
        _lru(owner, '_extract_cached')
        if state != 'cold':
            for _ in range(3):
                result = owner._extract_cached(_PHP, ('escapeshellcmd',))
                assert isinstance(result, (owner.ChainExtraction, owner.ExtractionRefusal))
        slots = [(execute, '_RESOLVED', execute._RESOLVE_LOCK), (owner, '_extract_cached', None)]
    else:
        owner = _view('packages.web._browser_sandbox')
        modules['boundary'] = owner
        owner._INNER_PROBE_STATE = threading.local()
        if state.endswith('_false'):
            owner._INNER_PROBE_STATE.active = False
        elif state.endswith('_true'):
            owner._INNER_PROBE_STATE.active = True
        engine = MagicMock()
        engine.__enter__.return_value = engine
        engine._launch_kwargs = {}
        page = engine._context.new_page.return_value
        page.evaluate.return_value = 2
        page.screenshot.return_value = b'\x89PNG\r\n\x1a\n'
        def importing(name, globals=None, locals=None, fromlist=(), level=0):
            if name == 'packages.web.browser':
                return SimpleNamespace(BrowserEngine=lambda *args, **kwargs: engine)
            return builtins.__import__(name, globals, locals, fromlist, level)
        vars(owner)['__builtins__'] = {**vars(builtins), '__import__': importing}
        _lru(owner, 'macos_nested_seatbelt_available')
        if state.startswith('warm_'):
            for _ in range(3):
                assert owner.macos_nested_seatbelt_available() is True
            if state.endswith('_missing'):
                del owner._INNER_PROBE_STATE.active
        slots = [(owner, 'macos_nested_seatbelt_available', None), (owner, '_INNER_PROBE_STATE', None)]
    return modules, slots


def _consume(kind, modules, tmp_path):
    if kind == 'model':
        owner = modules['audit_bridge']
        model = owner._load_cached(str(tmp_path / 'domain-model.json'))
        assert isinstance(owner._slice_memo_for(model), owner._DomainSliceMemo)
    elif kind == 'control':
        modules['sweep']._negative_control_cache[('body', 'c', '.c')] = False
    elif kind == 'sanwit':
        execute, owner = modules['sanwit_execute'], modules['sanwit']
        with execute._RESOLVE_LOCK:
            execute._RESOLVED = execute.PhpRuntime(tier='native', version='8.3.0', php_path='/owned/body/php')
        assert isinstance(owner._extract_cached(_PHP, ('escapeshellcmd',)), (owner.ChainExtraction, owner.ExtractionRefusal))
    else:
        owner = modules['boundary']
        assert owner.macos_nested_seatbelt_available() is True
        assert owner._INNER_PROBE_STATE.active is False


def _snapshot(value):
    if hasattr(value, 'cache_info'):
        return value.cache_info()
    if isinstance(value, OrderedDict):
        return [(key, id(memo), copy.deepcopy(memo.model)) for key, memo in value.items()]
    if isinstance(value, threading.local):
        return dict(vars(value))
    return copy.deepcopy(value)


def _cases():
    for kind, file, fixture, states, count in _SITES:
        for state in states:
            for mode in ('normal', 'body_error', 'body_interrupt'):
                yield pytest.param(kind, file, fixture, state, mode, None, id=f'{kind}-{state}-{mode}')
            for publication in range(count):
                for mode in ('setup_error', 'setup_interrupt'):
                    yield pytest.param(kind, file, fixture, state, mode, publication,
                                       id=f'{kind}-{state}-{mode}-{publication}')


@pytest.mark.parametrize('kind,file,fixture_name,state,mode,publication', list(_cases()))
def test_actual_probe_fixture_preserves_borrowed_state(kind, file, fixture_name, state, mode, publication, tmp_path):
    modules, slots = _prepare(kind, state, tmp_path)
    borrowed = [getattr(owner, name) for owner, name, lock in slots]
    saved = [_snapshot(value) for value in borrowed]
    failure = KeyboardInterrupt('owned interruption') if mode.endswith('interrupt') else RuntimeError('owned failure')
    published = []

    class Patcher(pytest.MonkeyPatch):
        def setattr(self, obj, name, value, *args, **kwargs):
            super().setattr(obj, name, value, *args, **kwargs)
            for index, (owner, field, lock) in enumerate(slots):
                if obj is owner and name == field:
                    published.append(index)
                    assert lock is None or lock.held
                    if mode.startswith('setup_') and publication == index:
                        raise failure

    raw = isolated_module_state.__wrapped__
    clone = FunctionType(raw.__code__, {**raw.__globals__, 'pytest': SimpleNamespace(MonkeyPatch=Patcher)}, argdefs=raw.__defaults__)
    clone.__kwdefaults__ = raw.__kwdefaults__
    helper = contextmanager(clone)
    def importing(name, globals=None, locals=None, fromlist=(), level=0):
        if name == 'core.concepts':
            return SimpleNamespace(audit_bridge=modules['audit_bridge'])
        if name == 'core.audit':
            return SimpleNamespace(**{key: value for key, value in modules.items() if key in ('sweep', 'sanwit')})
        if name == 'core.testing.module_state':
            return SimpleNamespace(isolated_module_state=helper)
        return builtins.__import__(name, globals, locals, fromlist, level)
    namespace = {**modules, 'isolated_module_state': helper,
                 '__builtins__': {**vars(builtins), '__import__': importing}}
    node = copy.deepcopy(next(n for n in ast.parse((_ROOT / file).read_text()).body if isinstance(n, ast.FunctionDef) and n.name == fixture_name))
    node.decorator_list = []
    exec(compile(ast.Module(body=[node], type_ignores=[]), file, 'exec'), namespace)
    reached = []
    def execute():
        patch = pytest.MonkeyPatch()
        fixture = namespace[fixture_name](patch)
        try:
            next(fixture)
            reached.append(True)
            for (owner, name, lock), original in zip(slots, borrowed):
                private = getattr(owner, name)
                assert lock is None or not lock.held
                if hasattr(private, 'cache_info'):
                    assert private is not original and private.cache_info().currsize == 0
                    assert private.cache_parameters() == original.cache_parameters()
                elif name == '_RESOLVED':
                    assert private is None
                else:
                    assert private is not original and not _snapshot(private)
            _consume(kind, modules, tmp_path)
            for owner, name, lock in slots:
                if hasattr(getattr(owner, name), 'cache_info'):
                    patch.setattr(owner, name, lambda *args: None)
                    break
            if mode.startswith('body_'):
                raise failure
        finally:
            try:
                fixture.close()
            finally:
                patch.undo()
    if mode == 'normal':
        execute()
    else:
        with pytest.raises(type(failure)) as caught:
            execute()
        assert caught.value is failure
    assert bool(reached) is (not mode.startswith('setup_'))
    assert published
    for (owner, name, lock), original, snapshot in zip(slots, borrowed, saved):
        assert getattr(owner, name) is original
        assert _snapshot(original) == snapshot
        if lock is not None:
            assert not lock.held and lock.acquisitions >= 2

"""Resolver probe fixtures preserve caller answers and calibration bindings."""
import ast
import builtins
from contextlib import contextmanager
import importlib
from pathlib import Path
from types import FunctionType, ModuleType, SimpleNamespace

import pytest
from core.testing.module_state import isolated_module_state

_ROOT = Path(__file__).resolve().parents[3]
_FILE = 'packages/sca/resolvers/tests/test_resolvers.py'


def _view(name):
    owner = ModuleType(name)
    vars(owner).update(vars(importlib.import_module(name)))
    return owner


@pytest.mark.parametrize('warm', [False, True])
@pytest.mark.parametrize('mode,publication', [
    ('normal', None), ('body_error', None), ('body_interrupt', None),
    ('setup_error', 0), ('setup_interrupt', 0),
    ('setup_error', 1), ('setup_interrupt', 1),
    ('setup_error', 2), ('setup_interrupt', 2),
])
def test_actual_resolver_fixture_preserves_borrowed_probe_answers(warm, mode, publication):
    state = _view('core.sandbox.state')
    profile = _view('packages.sca.resolvers._proxy_hosts')
    state._net_available_cache = True if warm else None
    state._mount_available_cache = False if warm else None
    borrowed = state._net_available_cache, state._mount_available_cache, profile._calibrated_profile
    failure = KeyboardInterrupt('owned interruption') if mode.endswith('interrupt') else RuntimeError('owned failure')
    publications = []

    class Patcher(pytest.MonkeyPatch):
        def setattr(self, obj, name, value, *args, **kwargs):
            super().setattr(obj, name, value, *args, **kwargs)
            index = (0 if obj is state and name == '_net_available_cache'
                     else 1 if obj is state and name == '_mount_available_cache'
                     else 2 if obj is profile and name == '_calibrated_profile' else None)
            if index is not None:
                publications.append(index)
                if mode.startswith('setup_') and publication == index:
                    raise failure

    original = isolated_module_state.__wrapped__
    clone = FunctionType(original.__code__, {**original.__globals__, 'pytest': SimpleNamespace(MonkeyPatch=Patcher)}, argdefs=original.__defaults__)
    clone.__kwdefaults__ = original.__kwdefaults__
    helper = contextmanager(clone)
    def importing(name, globals=None, locals=None, fromlist=(), level=0):
        if name == 'core.sandbox':
            return SimpleNamespace(state=state)
        if name == 'packages.sca.resolvers':
            return SimpleNamespace(_proxy_hosts=profile)
        if name == 'core.testing.module_state':
            return SimpleNamespace(isolated_module_state=helper)
        return builtins.__import__(name, globals, locals, fromlist, level)
    namespace = {'__builtins__': {**vars(builtins), '__import__': importing}}
    node = next(n for n in ast.parse((_ROOT / _FILE).read_text()).body if isinstance(n, ast.FunctionDef) and n.name == '_reset_sandbox_probe_caches')
    node.decorator_list = []
    exec(compile(ast.Module(body=[node], type_ignores=[]), _FILE, 'exec'), namespace)
    reached = []
    def execute():
        patch = Patcher()
        fixture = namespace[node.name](patch)
        try:
            next(fixture)
            reached.append(True)
            assert state._net_available_cache is None
            assert state._mount_available_cache is None
            assert profile._calibrated_profile is not borrowed[2]
            assert profile._calibrated_profile() is None
            patch.setattr(state, '_net_available_cache', False)
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
    assert publications
    assert state._net_available_cache is borrowed[0]
    assert state._mount_available_cache is borrowed[1]
    assert profile._calibrated_profile is borrowed[2]

"""Native discovery and descriptor mocks own their function-local imports."""

import ast
import builtins
from contextlib import contextmanager
import importlib
import os
from pathlib import Path
import shutil
from types import ModuleType
from unittest.mock import Mock, patch

import pytest

from core.testing.module_bindings import mock_module_attribute, patch_module_attribute
from core.testing.module_views import module_function_view, scoped_function_imports


ROOT = Path(__file__).resolve().parents[3]
CASES = [
    ('core.llm.dispatcher.tests.test_f085_spawn_default_env', 'test_spawn_worker_env_none_defaults_to_safe_env', 0),
    ('core.llm.dispatcher.tests.test_f085_spawn_default_env', 'test_spawn_worker_env_none_preserves_operator_proxy', 0),
    ('core.llm.dispatcher.tests.test_f085_spawn_default_env', 'test_spawn_worker_env_none_carries_routing_family_not_secrets', 0),
    ('core.llm.dispatcher.tests.test_f085_spawn_default_env', 'test_spawn_worker_explicit_env_not_overlaid', 0),
    ('core.llm.tests.test_bedrock_entry_resolution', 'test_claudecode_entry_auth_resolvable_via_binary', 0),
    ('core.llm.tests.test_bedrock_entry_resolution', 'test_claudecode_entry_auth_resolvable_via_binary', 1),
    ('core.llm.tests.test_bedrock_entry_resolution', 'test_claudecode_fallback_behind_bedrock_primary', 0),
    ('core.llm.tests.test_ollama_primary_resolution', '_isolated_env', 0),
    ('core.llm.tests.test_ollama_primary_resolution', '_claude_on_path', 0),
]


def _call(module, name, index):
    tree = ast.parse(Path(module.__file__).read_text())
    function = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name)
    calls = [n for n in ast.walk(function) if isinstance(n, ast.Call)
             and any(isinstance(a, ast.Constant) and a.value in ('os.close', 'shutil.which', 'close', 'which')
                     for a in n.args)]
    assert len(calls) == (2 if name == 'test_claudecode_entry_auth_resolvable_via_binary' else 1)
    return sorted(calls, key=lambda n: (n.lineno, n.col_offset))[index]


@pytest.mark.parametrize('module_name,name,index', CASES)
@pytest.mark.parametrize('finish', ['normal', 'error', 'interrupt'])
def test_native_import_override_is_private(module_name, name, index, finish, tmp_path):
    module = importlib.import_module(module_name)
    fixture = getattr(module, '_owned_spawn_imports' if 'spawn' in module_name else '_isolated_env', None)
    scope = pytest.MonkeyPatch()
    generator = None
    original_close, original_which = os.close, shutil.which
    try:
        if fixture is not None:
            kwargs = {'monkeypatch': scope}
            if 'tmp_path' in fixture.__wrapped__.__code__.co_varnames:
                kwargs['tmp_path'] = tmp_path
            generator = fixture.__wrapped__(**kwargs)
            next(generator)
        assert os.close is original_close
        assert shutil.which is original_which
        imports = getattr(module, '_local_imports', None)
        namespace = dict(patch=patch, monkeypatch=scope, _local_imports=imports,
                         mock_module_attribute=mock_module_attribute,
                         patch_module_attribute=patch_module_attribute)
        call = _call(module, name, index)
        context = eval(compile(ast.Expression(call), module.__file__, 'eval'), namespace)
        if isinstance(call.func, ast.Name) and call.func.id == 'patch_module_attribute' or (
            isinstance(call.func, ast.Attribute) and call.func.attr == 'setattr'
        ):
            from contextlib import nullcontext
            context = nullcontext()
        with context:
            assert os.close is original_close
            assert shutil.which is original_which
            if 'spawn' in module_name:
                from core.llm.dispatcher import spawn
                dispatcher = Mock()
                dispatcher.allocate_worker.return_value = ('fixture.sock', -1)
                with mock_module_attribute(spawn, 'subprocess', 'Popen', return_value='owned child'):
                    assert spawn.spawn_worker(dispatcher, ['fixture-child'], label='fixture', env={}) == 'owned child'
                imports.os.close.assert_called_once_with(-1)
            else:
                from core.llm import config
                scope.setattr(config, '_resolve_claudecode_model', lambda: config.CLAUDECODE_SESSION_MODEL)
                expected = imports.shutil.which('claude') is not None
                model = config.ModelConfig(provider='claudecode', model_name='session-default')
                assert config._entry_auth_resolvable(model) is expected
                assert (config._build_claudecode_config() is not None) is expected
            if finish == 'error':
                raise RuntimeError('owned exit')
            if finish == 'interrupt':
                raise KeyboardInterrupt('owned exit')
    except (RuntimeError, KeyboardInterrupt) as error:
        assert type(error) is {'error': RuntimeError, 'interrupt': KeyboardInterrupt}.get(finish)
    finally:
        if generator is not None:
            generator.close()
        scope.undo()
        assert os.close is original_close
        assert shutil.which is original_which


@pytest.mark.parametrize('builtins_kind', ['dict', 'module'])
@pytest.mark.parametrize('finish', ['normal', 'error', 'interrupt'])
@pytest.mark.parametrize('late_binding', [False, True])
def test_import_scope_keeps_live_globals_and_inherited_hook(builtins_kind, finish, late_binding):
    calls = []
    inherited = builtins.__import__

    def record(name, globals=None, locals=None, fromlist=(), level=0):
        calls.append(name)
        return inherited(name, globals, locals, fromlist, level)

    owner = ModuleType('owned_functions')
    private_builtins = dict(vars(builtins), __import__=record)
    if builtins_kind == 'module':
        view = ModuleType('builtins')
        vars(view).update(private_builtins)
        private_builtins = view
    owner.__builtins__ = private_builtins
    exec('def read():\n import os\n import math\n return os.getcwd(), math.sqrt(9), token\n', vars(owner))
    original = owner.read
    token = object()
    owner.token = token
    try:
        with scoped_function_imports(owner, ('read',), {'os': os}) as imports:
            imports.os.getcwd = lambda: 'private'
            if late_binding:
                owner.token = 'late'
            assert owner.read() == ('private', 3.0, 'late' if late_binding else token)
            assert calls == ['math']
            assert builtins.__import__ is inherited
            assert owner.__builtins__ is private_builtins
            if finish == 'error':
                raise RuntimeError('owned exit')
            if finish == 'interrupt':
                raise KeyboardInterrupt('owned exit')
    except (RuntimeError, KeyboardInterrupt) as error:
        assert type(error) is {'error': RuntimeError, 'interrupt': KeyboardInterrupt}.get(finish)
    finally:
        assert owner.read is original
        assert builtins.__import__ is inherited


@pytest.mark.parametrize('fail_at', [1, 2])
@pytest.mark.parametrize('error', [OSError, KeyboardInterrupt])
def test_import_scope_rolls_back_partial_publication(fail_at, error):
    from core.testing import module_views

    class FailingPatch(pytest.MonkeyPatch):
        def setitem(self, *args, **kwargs):
            super().setitem(*args, **kwargs)
            self.calls = getattr(self, 'calls', 0) + 1
            if self.calls == fail_at:
                raise error('publication failed')

    pytest_view = ModuleType('pytest')
    vars(pytest_view).update(vars(pytest))
    pytest_view.MonkeyPatch = FailingPatch

    def import_local(name, globals=None, locals=None, fromlist=(), level=0):
        if name == 'pytest':
            return pytest_view
        return builtins.__import__(name, globals, locals, fromlist, level)

    private = module_function_view(module_views, bindings={
        'scoped_function_imports': scoped_function_imports.__wrapped__,
    }, import_hook=import_local)
    owner = ModuleType('owned_functions')
    exec('def one(): return 1\ndef two(): return 2\n', vars(owner))
    before = (owner.one, owner.two)
    with pytest.raises(error, match='publication failed'):
        with contextmanager(private.scoped_function_imports)(owner, ('one', 'two'), {'os': os}):
            pytest.fail('body entered after publication failure')
    assert (owner.one, owner.two) == before


@pytest.mark.parametrize('override', [False, True])
@pytest.mark.parametrize('finish', ['normal', 'error', 'interrupt'])
def test_selected_callee_keeps_body_override(override, finish):
    owner = ModuleType('selected_functions')
    exec('def first(): return second()\ndef second():\n import os\n return os.getcwd()\n', vars(owner))
    originals = (owner.first, owner.second)
    try:
        with scoped_function_imports(owner, ('first', 'second'), {'os': os}) as imports:
            imports.os.getcwd = lambda: 'owned directory'
            with pytest.MonkeyPatch.context() as body:
                if override:
                    replacement = Mock(return_value='body override')
                    body.setattr(owner, 'second', replacement)
                assert owner.first() == ('body override' if override else 'owned directory')
                if override:
                    replacement.assert_called_once_with()
                if finish == 'error':
                    raise RuntimeError('owned exit')
                if finish == 'interrupt':
                    raise KeyboardInterrupt('owned exit')
    except (RuntimeError, KeyboardInterrupt) as error:
        assert type(error) is {'error': RuntimeError, 'interrupt': KeyboardInterrupt}.get(finish)
    finally:
        assert (owner.first, owner.second) == originals


def test_selected_lazy_binding_restores_raw_absence():
    owner = ModuleType('lazy_functions')
    exec('def original():\n import os\n return os.getcwd()\n', vars(owner))
    owner.__getattr__ = lambda name: owner.original if name == 'lazy' else None
    assert 'lazy' not in vars(owner)
    with scoped_function_imports(owner, ('lazy',), {'os': os}) as imports:
        imports.os.getcwd = lambda: 'owned directory'
        assert owner.lazy() == 'owned directory'
    assert 'lazy' not in vars(owner)
    assert owner.lazy is owner.original

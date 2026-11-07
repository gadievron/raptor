"""Update-probe mocks own HTTP and import state through failure and teardown."""

import ast
import builtins
from importlib import import_module
from pathlib import Path
from types import FunctionType
from unittest import mock

import pytest
import requests

from core.startup import init
from core.testing.module_bindings import mock_module_attribute
from core.testing.module_views import module_function_view

ROOT = Path(__file__).resolve().parents[3]
FILE = 'core/startup/tests/test_check_tools.py'
CASES = [
    'test_returns_true_when_newer',
    'test_returns_false_when_same',
    'test_returns_false_on_network_error',
    'test_returns_false_when_requests_missing',
    'test_cached_result_avoids_network',
    'test_stale_cache_triggers_fetch',
]


def _function(name):
    tree = ast.parse((ROOT / FILE).read_text())
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'TestCheckPypiUpdate')
    return next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == name)


@pytest.mark.parametrize('name', CASES)
@pytest.mark.parametrize('finish', ['normal', 'error', 'interrupt'])
def test_native_pypi_mock_is_private(name, finish, tmp_path):
    module = import_module('core.startup.tests.test_check_tools')
    original_import, original_get, original_check = builtins.__import__, requests.get, init._check_pypi_update
    previous = vars(module).get('_update_imports', None)
    patcher = pytest.MonkeyPatch()
    generator = None
    try:
        patcher.setenv('XDG_CACHE_HOME', str(tmp_path / 'cache'))
        fixture = getattr(module, '_owned_update_imports', None)
        if fixture is not None:
            generator = fixture.__wrapped__(patcher)
            next(generator)
        function = _function(name)
        calls = [n for n in ast.walk(function) if isinstance(n, ast.Call)
                 and any(isinstance(a, ast.Constant) and a.value in ('requests.get', 'builtins.__import__', 'get', '__import__') for a in n.args)]
        assert len(calls) == 1
        namespace = dict(mock=mock, mock_module_attribute=mock_module_attribute,
                         _update_imports=getattr(module, '_update_imports', None),
                         resp=mock.Mock(status_code=200), _req=requests,
                         real_import=original_import)
        namespace['resp'].json.return_value = {'info': {'version': '1.83.0'}}
        if name == 'test_returns_false_when_requests_missing':
            block = next(n for n in function.body if isinstance(n, ast.FunctionDef))
            exec(compile(ast.Module(body=[block], type_ignores=[]), FILE, 'exec'), namespace)
        with eval(compile(ast.Expression(calls[0]), FILE, 'eval'), namespace) as patched:
            assert builtins.__import__ is original_import
            assert requests.get is original_get
            imports = module._update_imports
            if name == 'test_returns_false_when_requests_missing':
                assert imports.builtins.__import__ is patched
                assert original_import('requests') is requests
                assert init._check_pypi_update('owned-missing-package', '0.0') is False
            else:
                assert imports.requests.get is patched
                assert imports.builtins.__import__('requests') is imports.requests
                assert isinstance(init._check_pypi_update('owned-update-package', '0.0'), bool)
                patched.assert_called_once_with('https://pypi.org/pypi/owned-update-package/json', timeout=2)
            if finish == 'error':
                raise RuntimeError('owned exit')
            if finish == 'interrupt':
                raise KeyboardInterrupt('owned exit')
    except (RuntimeError, KeyboardInterrupt) as error:
        assert type(error) is {'error': RuntimeError, 'interrupt': KeyboardInterrupt}.get(finish)
    finally:
        if generator is not None:
            generator.close()
        patcher.undo()
        assert init._check_pypi_update is original_check
        assert builtins.__import__ is original_import
        assert requests.get is original_get
        assert vars(module).get('_update_imports', None) is previous


@pytest.mark.parametrize('fail_at', [1, 2])
@pytest.mark.parametrize('error', [OSError, KeyboardInterrupt])
def test_fixture_setup_failure_restores_publications(fail_at, error):
    module = import_module('core.startup.tests.test_check_tools')
    before = init._check_pypi_update
    imports = module._update_imports

    class FailingPatch(pytest.MonkeyPatch):
        def setitem(self, *args, **kwargs):
            super().setitem(*args, **kwargs)
            self.calls = getattr(self, 'calls', 0) + 1
            if self.calls == fail_at:
                raise error('publication failed')

    patcher = FailingPatch()
    generator = module._owned_update_imports.__wrapped__(patcher)
    try:
        with pytest.raises(error, match='publication failed'):
            next(generator)
        assert init._check_pypi_update is before
        assert module._update_imports is imports
    finally:
        generator.close()
        patcher.undo()


@pytest.mark.parametrize('finish', ['normal', 'error', 'interrupt'])
def test_missing_import_uses_inherited_hook(finish, tmp_path):
    module = import_module('core.startup.tests.test_check_tools')
    original_import = builtins.__import__
    original_get = requests.get
    calls = []

    def absent(name, globals=None, locals=None, fromlist=(), level=0):
        if name == 'requests':
            calls.append(name)
            raise ImportError('owned missing dependency')
        return original_import(name, globals, locals, fromlist, level)

    view = module_function_view(init, import_hook=absent)
    original = view._check_pypi_update
    generator = None
    patcher = pytest.MonkeyPatch()
    try:
        patcher.setenv('XDG_CACHE_HOME', str(tmp_path / 'cache'))
        fixture = getattr(module, '_owned_update_imports', None)
        if fixture is not None:
            raw = fixture.__wrapped__
            owned = FunctionType(raw.__code__, {**raw.__globals__, 'startup_init': view})
            generator = owned(patcher)
            next(generator)
        assert view._check_pypi_update('owned-missing-package', '0.0') is False
        assert calls
        assert builtins.__import__ is original_import
        assert requests.get is original_get
        if finish == 'error':
            raise RuntimeError('owned exit')
        if finish == 'interrupt':
            raise KeyboardInterrupt('owned exit')
    except (RuntimeError, KeyboardInterrupt) as error:
        assert type(error) is {'error': RuntimeError, 'interrupt': KeyboardInterrupt}.get(finish)
    finally:
        if generator is not None:
            generator.close()
        patcher.undo()
        assert view._check_pypi_update is original

"""Test collection leaves borrowed interpreter and installation state alone."""

from contextlib import contextmanager
from functools import lru_cache
import ast
import importlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import sys

import pytest

_ROOT = Path(__file__).resolve().parents[3]
_SITES = json.loads((Path(__file__).parent / 'data/collection_bootstrap_sites.json').read_text())
_BASELINE = None


def _source(file):
    return ((_BASELINE / file).read_text() if _BASELINE is not None
            else (_ROOT / file).read_text())


def _fullname(file):
    return file.removesuffix('.py').replace('/', '.')


def _set_caller(patch, marker):
    if marker is None:
        patch.delenv('RAPTOR_DIR', raising=False)
    else:
        patch.setenv('RAPTOR_DIR', marker)
    # A lexical alias still supports real imports, while ensuring an old
    # "if root not in sys.path" bootstrap cannot silently avoid its mutation.
    path = [entry for entry in sys.path if Path(entry or '.').resolve() != _ROOT]
    path += [str(_ROOT) + '/.', '/owned/duplicate', '/owned/duplicate']
    patch.setattr(sys, 'path', path)
    return dict(os.environ), path, list(path)


def _assert_caller(before):
    environment, path, values = before
    assert dict(os.environ) == environment
    assert sys.path is path
    assert sys.path == values


@lru_cache(maxsize=None)
def _bootstrap_code(file, fail):
    tree = ast.parse(_source(file))
    ends = []
    for statement in tree.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if any(isinstance(node, ast.Call) and ast.unparse(node.func) == 'sys.path.insert'
               for node in ast.walk(statement)):
            ends.append(statement.end_lineno)
    assert ends, file
    # Execute the actual native startup through its last path bootstrap.
    # Later compiler setup and dynamic product imports belong to the native
    # suites, which run separately with pytest's required launch environment.
    tree.body = [statement for statement in tree.body if statement.lineno <= max(ends)]
    if fail:
        tree.body.append(ast.Raise(exc=ast.Name(id='_collection_failure', ctx=ast.Load()), cause=None))
    ast.fix_missing_locations(tree)
    return compile(tree, str(_ROOT / file), 'exec')


@pytest.mark.parametrize('file', _SITES, ids=_SITES)
@pytest.mark.parametrize('marker', [None, '', '/owned/other-checkout'],
                         ids=['missing', 'empty', 'borrowed'])
@pytest.mark.parametrize('outcome', ['normal', 'error', 'interrupt'])
def test_native_bootstrap_preserves_caller(file, marker, outcome, monkeypatch):
    name = _fullname(file)
    failure = RuntimeError('collection failed') if outcome == 'error' else KeyboardInterrupt('collection interrupted')

    class Loader(importlib.machinery.SourceFileLoader):
        def get_code(self, fullname):
            return _bootstrap_code(file, outcome != 'normal')

    loader = Loader(name, str(_ROOT / file))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(name, loader))
    module._collection_failure = failure
    missing = object()
    original = sys.modules.get(name, missing)
    # Warm only ordinary bootstrap dependencies under the valid launch pin.
    # The private path object contains any legacy baseline mutation here.
    with pytest.MonkeyPatch.context() as warm:
        warm.setenv('RAPTOR_DIR', str(_ROOT))
        warm.setattr(sys, 'path', list(sys.path))
        exec(_bootstrap_code(file, False), vars(module))
    with pytest.MonkeyPatch.context() as publish:
        publish.setitem(sys.modules, name, module)
        before = _set_caller(monkeypatch, marker)
        if outcome == 'normal':
            loader.exec_module(module)
        else:
            with pytest.raises(type(failure)) as caught:
                loader.exec_module(module)
            assert caught.value is failure
        _assert_caller(before)
    if original is missing:
        assert name not in sys.modules
    else:
        assert sys.modules[name] is original


@pytest.mark.parametrize('file', [
    'core/audit/tests/test_checker_library.py',
    'core/sandbox/tests/test_proxy_netns_enforcement.py',
])
@pytest.mark.parametrize('marker', [None, '', '/owned/other-checkout'],
                         ids=['missing', 'empty', 'borrowed'])
@pytest.mark.parametrize('outcome', ['normal', 'error', 'interrupt'])
def test_native_root_fixture_owns_only_its_lifetime(file, marker, outcome, monkeypatch):
    native = importlib.import_module(_fullname(file))
    before = _set_caller(monkeypatch, marker)
    failure = RuntimeError('owned body failed') if outcome == 'error' else KeyboardInterrupt('owned body interrupted')

    @contextmanager
    def body():
        with pytest.MonkeyPatch.context() as owner:
            native._owned_install_dir.__wrapped__(owner)
            assert os.environ['RAPTOR_DIR'] == str(_ROOT)
            yield

    if outcome == 'normal':
        with body():
            assert sys.path is before[1]
    else:
        with pytest.raises(type(failure)) as caught:
            with body():
                raise failure
        assert caught.value is failure
    _assert_caller(before)

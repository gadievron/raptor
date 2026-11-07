"""Native mock contexts own their bindings without file-wide fixture setup."""

import ast
from functools import lru_cache
import json
from pathlib import Path
from pkgutil import resolve_name
from types import ModuleType
from unittest import mock

import pytest

from core.testing.mock_sources import as_patch_call
from core.testing.module_bindings import mock_module_attribute

ROOT = Path(__file__).resolve().parents[3]
SITES = json.loads((Path(__file__).parent / 'data/native_mock_context_sites.json').read_text())


@lru_cache(maxsize=None)
def _calls(file):
    tree = ast.parse((ROOT / file).read_text())
    parents = {id(child): node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    found = {}
    for call in ast.walk(tree):
        if not isinstance(call, ast.Call):
            continue
        normalized = as_patch_call(call)
        if not normalized.args or not isinstance(normalized.args[0], ast.Constant):
            continue
        if not (isinstance(normalized.func, ast.Name) and normalized.func.id == 'patch'
                or isinstance(normalized.func, ast.Attribute) and normalized.func.attr == 'patch'):
            continue
        target = normalized.args[0].value
        anchor = []
        node = call
        while id(node) in parents:
            node = parents[id(node)]
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                anchor.append(node.name)
        found.setdefault((tuple(reversed(anchor)), target), []).append(call)
    return {key: sorted(values, key=lambda n: (n.lineno, n.col_offset)) for key, values in found.items()}


def _unchanged(owner, before):
    assert set(vars(owner)) == set(before)
    assert all(vars(owner)[name] is value for name, value in before.items())


@pytest.mark.parametrize('site', SITES, ids=[f"{s['file']}:{'.'.join(s['anchor'])}:{s['binding']}.{s['attribute']}:{s['ordinal']}" for s in SITES])
@pytest.mark.parametrize('borrowed_view', [False, True], ids=['ordinary', 'borrowed'])
@pytest.mark.parametrize('finish', ['normal', 'error', 'interrupt'])
def test_native_context_owns_namespace(site, borrowed_view, finish):
    owner = resolve_name(site['owner'])
    assert isinstance(owner, ModuleType)
    binding, attribute = site['binding'], site['attribute']
    borrowed = getattr(owner, binding)
    assert isinstance(borrowed, ModuleType)
    target = '.'.join((site['owner'], binding, attribute))
    key = (tuple(site['anchor']), target)
    actual = _calls(site['file'])[key][site['ordinal']]
    with pytest.MonkeyPatch.context() as inherited:
        if borrowed_view:
            private = ModuleType(borrowed.__name__)
            vars(private).update(vars(borrowed))
            inherited.setitem(vars(owner), binding, private)
        borrowed = getattr(owner, binding)
        before = dict(vars(borrowed))
        original = getattr(borrowed, attribute, None)
        replacement = mock.MagicMock(wraps=original) if callable(original) else object()
        # Exercise the native target and context factory. Configuration and
        # payload behavior remain covered by the unchanged native assertions;
        # no worker, kernel operation or tool is invoked by this scope check.
        call = ast.parse(ast.unparse(actual), mode='eval').body
        prefix = 3 if isinstance(call.func, ast.Name) and call.func.id == 'mock_module_attribute' else 1
        call.args = call.args[:prefix] + [ast.Name(id='replacement', ctx=ast.Load())]
        call.keywords = [ast.keyword(arg='create', value=ast.Constant(True))]
        ast.fix_missing_locations(call)
        namespace = dict(mock=mock, patch=mock.patch, mock_module_attribute=mock_module_attribute,
                         _mock_owner=resolve_name, replacement=replacement)
        try:
            with eval(compile(ast.Expression(call), site['file'], 'eval'), namespace) as patched:
                assert patched is replacement
                assert getattr(owner, binding) is not borrowed
                assert getattr(getattr(owner, binding), attribute) is replacement
                _unchanged(borrowed, before)
                if finish == 'error':
                    raise RuntimeError('owned exit')
                if finish == 'interrupt':
                    raise KeyboardInterrupt('owned exit')
        except (RuntimeError, KeyboardInterrupt) as error:
            assert type(error) is {'error': RuntimeError, 'interrupt': KeyboardInterrupt}.get(finish)
        finally:
            assert getattr(owner, binding) is borrowed
            _unchanged(borrowed, before)


@pytest.mark.parametrize('text', [
    "patch('owner.subprocess.run', return_value=1)",
    "mock.patch('owner.subprocess.run', autospec=True)",
    "mock_module_attribute(owner, 'subprocess', 'run')",
    "mock_module_attribute(_mock_owner(variable), 'subprocess', 'run')",
    "mock_module_attribute(_mock_owner('owner'), variable, 'run')",
])
def test_unrecognized_source_passes_through(text):
    node = ast.parse(text, mode='eval').body
    assert as_patch_call(node) is node


def test_normalized_source_keeps_configuration_and_location():
    original = ast.parse("mock_module_attribute(_mock_owner('owner'), 'subprocess', 'run', value, autospec=True, create=False)", mode='eval').body
    before = ast.dump(original, include_attributes=True)
    normalized = as_patch_call(original)
    assert ast.unparse(normalized) == "patch('owner.subprocess.run', value, autospec=True, create=False)"
    assert normalized.lineno == original.lineno
    assert ast.dump(original, include_attributes=True) == before


@pytest.mark.parametrize('finish', ['normal', 'error', 'interrupt'])
def test_codeql_cache_lifetime_stays_outside_target(finish, tmp_path):
    from importlib import import_module
    import inspect
    import shutil

    module = import_module('packages.codeql.tests.test_buildless_mode')
    before = module.DatabaseManager.__init__
    result = module.db_manager.__wrapped__(tmp_path)
    generator = result if inspect.isgenerator(result) else None
    manager = next(generator) if generator is not None else result
    root = manager.db_root
    try:
        assert root.parent == tmp_path.parent
        assert root != tmp_path
        assert root.is_dir()
        assert module.DatabaseManager.__init__ is before
        (root / 'owned-cache-row').write_text('fixture cache')
        if finish == 'error':
            raise RuntimeError('owned exit')
        if finish == 'interrupt':
            raise KeyboardInterrupt('owned exit')
    except (RuntimeError, KeyboardInterrupt) as error:
        assert type(error) is {'error': RuntimeError, 'interrupt': KeyboardInterrupt}.get(finish)
    finally:
        if generator is not None:
            generator.close()
        try:
            assert not root.exists(), 'cache outlived its owning fixture'
        finally:
            if root.exists():
                shutil.rmtree(root)


def test_codeql_cache_does_not_reuse_retained_sibling(tmp_path, request):
    import shutil
    from importlib import import_module
    import inspect

    module = import_module('packages.codeql.tests.test_buildless_mode')
    retained = tmp_path.parent / (tmp_path.name + '-cache')
    retained.mkdir()
    request.addfinalizer(lambda: shutil.rmtree(retained))
    marker = retained / 'caller-row'
    marker.write_text('retained sibling')
    for _ in range(3):
        result = module.db_manager.__wrapped__(tmp_path)
        generator = result if inspect.isgenerator(result) else None
        manager = next(generator) if generator is not None else result
        try:
            assert manager.db_root != retained
            assert manager.db_root.is_dir()
        finally:
            if generator is not None:
                generator.close()
        assert not manager.db_root.exists()
    assert marker.read_text() == 'retained sibling'


@pytest.mark.parametrize('error', [OSError, KeyboardInterrupt])
def test_codeql_cache_constructor_failure_leaves_no_directory(error, tmp_path):
    from importlib import import_module
    import inspect
    from types import FunctionType

    module = import_module('packages.codeql.tests.test_buildless_mode')

    class BrokenManager(module.DatabaseManager):
        def __new__(cls):
            raise error('owned constructor failure')

    original = module.db_manager.__wrapped__
    private = FunctionType(original.__code__, {**original.__globals__, 'DatabaseManager': BrokenManager})
    before = set(tmp_path.parent.iterdir())
    with pytest.raises(error, match='owned constructor failure'):
        result = private(tmp_path)
        if inspect.isgenerator(result):
            next(result)
    assert set(tmp_path.parent.iterdir()) == before

"""Nested native fault sites own the selected branch and restore borrowed modules."""
import ast
from contextlib import ExitStack
from functools import lru_cache
import json
from pathlib import Path
from pkgutil import resolve_name
from types import ModuleType
from unittest import mock

import pytest

from core.testing.module_bindings import mock_module_attribute, patch_module_attribute

ROOT = Path(__file__).resolve().parents[3]
SITES = json.loads((Path(__file__).parent / 'data/nested_module_sites.json').read_text())


def _path(owner, binding):
    modules = []
    for name in binding.split('.'):
        owner = getattr(owner, name)
        assert isinstance(owner, ModuleType)
        modules.append(owner)
    return modules


def _unchanged(owner, before):
    assert set(vars(owner)) == set(before)
    assert all(vars(owner)[name] is value for name, value in before.items())


@lru_cache(maxsize=None)
def _native_call(file, anchor, current, original):
    tree = ast.parse((ROOT / file).read_text())
    parents = {id(child): node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    candidates = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        names = []
        parent = node
        while id(parent) in parents:
            parent = parents[id(parent)]
            if isinstance(parent, (ast.FunctionDef, ast.ClassDef)):
                names.append(parent.name)
        if tuple(reversed(names)) == anchor:
            candidates.append(node)
    for text in [current, original]:
        for node in candidates:
            if ast.unparse(node) == text:
                return node
    raise AssertionError((file, current))


@pytest.mark.parametrize('site', SITES, ids=[f"{s['file']}:{s['line']}" for s in SITES])
@pytest.mark.parametrize('borrowed_view', [False, True], ids=['ordinary', 'borrowed'])
@pytest.mark.parametrize('finish', ['normal', 'error', 'interrupt'])
def test_native_nested_site_owns_every_module(site, borrowed_view, finish):
    owner = resolve_name(site['owner'])
    binding, attribute = site['binding'], site['attribute']
    root_name = binding.split('.')[0]
    # Resolve lazy stdlib attributes before recording their borrowed namespaces.
    original = getattr(_path(owner, binding)[-1], attribute, None)
    replacement = mock.MagicMock(wraps=original) if callable(original) else object()
    actual = _native_call(site['file'], tuple(site['anchor']), site['new'], site['old'])
    call = ast.parse(ast.unparse(actual), mode='eval').body
    owned = getattr(call.func, 'id', '') in ('mock_module_attribute', 'patch_module_attribute')
    prefix = (3 if owned else 1) if site['kind'] == 'mock' else (4 if owned else 2)
    call.args = call.args[:prefix] + [ast.Name(id='replacement', ctx=ast.Load())]
    call.keywords = [ast.keyword(arg='create' if site['kind'] == 'mock' else 'raising',
                                value=ast.Constant(site['kind'] == 'mock'))]
    ast.fix_missing_locations(call)
    code = compile(ast.Expression(call), site['file'], 'eval')
    with pytest.MonkeyPatch.context() as inherited:
        if borrowed_view:
            root = getattr(owner, root_name)
            view = ModuleType(root.__name__)
            vars(view).update(vars(root))
            inherited.setitem(vars(owner), root_name, view)
        branches = _path(owner, binding)
        snapshots = [(branch, dict(vars(branch))) for branch in branches]
        owner_before = dict(vars(owner))
        with pytest.MonkeyPatch.context() as scope:
            namespace = dict(mock=mock, patch=mock.patch if site['kind'] == 'mock' else scope,
                             mock_patch=mock.patch, monkeypatch=scope, scoped=scope, scope=scope,
                             mock_module_attribute=mock_module_attribute,
                             patch_module_attribute=patch_module_attribute,
                             _mock_owner=resolve_name, replacement=replacement)
            if site['receiver'].isidentifier():
                namespace[site['receiver']] = owner
            if site['owner'] == 'core.sandbox.seccomp':
                namespace['ctypes'] = owner.ctypes
            try:
                with ExitStack() as stack:
                    result = eval(code, namespace)
                    if site['kind'] == 'mock':
                        assert stack.enter_context(result) is replacement
                    current = _path(owner, binding)
                    assert all(a is not b for a, b in zip(current, branches))
                    assert getattr(current[-1], attribute) is replacement
                    for branch, before in snapshots:
                        _unchanged(branch, before)
                    if finish == 'error':
                        raise RuntimeError('owned exit')
                    if finish == 'interrupt':
                        raise KeyboardInterrupt('owned exit')
            except (RuntimeError, KeyboardInterrupt) as error:
                assert type(error) is {'error': RuntimeError, 'interrupt': KeyboardInterrupt}.get(finish)
        _unchanged(owner, owner_before)
        for branch, before in snapshots:
            _unchanged(branch, before)


@pytest.mark.parametrize('binding,attribute', [
    ('os.path', 'realpath'), ('os.path.os', 'getpid'),
    ('importlib.util', 'find_spec'), ('urllib.request', 'urlopen'),
])
@pytest.mark.parametrize('style', ['monkey', 'mock'])
@pytest.mark.parametrize('lazy', ['neither', 'root', 'child'])
@pytest.mark.parametrize('finish', ['normal', 'error', 'interrupt'])
def test_nested_api_keeps_borrowed_graph_and_raw_absence(binding, attribute, style, lazy, finish):
    names = binding.split('.')
    owner = ModuleType('native_nested_binding_consumer')
    resolve_name(binding)
    root = resolve_name(names[0])
    # Use the actual stdlib modules and warm lazily imported descendants.
    actual = root
    for name in names[1:]:
        actual = getattr(actual, name)
    getattr(actual, attribute)
    if lazy == 'child':
        original = root
        root = ModuleType(original.__name__)
        vars(root).update(vars(original))
        child_name = names[1]
        child = getattr(root, child_name)
        del vars(root)[child_name]
        root.__getattr__ = lambda name: child if name == child_name else (_ for _ in ()).throw(AttributeError(name))
    if lazy == 'root':
        owner.__getattr__ = lambda name: root if name == names[0] else (_ for _ in ()).throw(AttributeError(name))
    else:
        setattr(owner, names[0], root)
    branches = _path(owner, binding)
    snapshots = [(owner, dict(vars(owner))), *[(branch, dict(vars(branch))) for branch in branches]]
    token = object()
    try:
        with pytest.MonkeyPatch.context() as scope, ExitStack() as stack:
            if style == 'monkey':
                leaf = patch_module_attribute(scope, owner, binding, attribute, token)
                assert leaf is _path(owner, binding)[-1]
            else:
                assert stack.enter_context(mock_module_attribute(owner, binding, attribute, new=token)) is token
            assert getattr(_path(owner, binding)[-1], attribute) is token
            assert all(a is not b for a, b in zip(_path(owner, binding), branches))
            for branch, before in snapshots[1:]:
                _unchanged(branch, before)
            if finish == 'error':
                raise RuntimeError('owned exit')
            if finish == 'interrupt':
                raise KeyboardInterrupt('owned exit')
    except (RuntimeError, KeyboardInterrupt) as error:
        assert type(error) is {'error': RuntimeError, 'interrupt': KeyboardInterrupt}.get(finish)
    for branch, before in snapshots:
        _unchanged(branch, before)


@pytest.mark.parametrize('style', ['monkey', 'mock'])
@pytest.mark.parametrize('invalid', ['missing_child', 'non_module', 'missing_attribute', 'mock_configuration'])
def test_setup_failure_never_leaves_partial_publication(style, invalid):
    import os
    owner = ModuleType('nested_setup_failure_consumer')
    owner.os = os
    before = dict(vars(owner))
    path = 'os.__missing_child' if invalid == 'missing_child' else 'os.name' if invalid == 'non_module' else 'os.path'
    attr = '__raptor_missing_nested_attribute__' if invalid == 'missing_attribute' else 'realpath'
    if invalid == 'mock_configuration' and style == 'monkey':
        path = 'os.path.__missing_child'
    with pytest.MonkeyPatch.context() as scope:
        with pytest.raises((AttributeError, TypeError)):
            if style == 'monkey':
                patch_module_attribute(scope, owner, path, attr, object())
            elif invalid == 'mock_configuration':
                with mock_module_attribute(owner, path, attr, new=object(), autospec=True):
                    pytest.fail('invalid mock configuration entered')
            else:
                with mock_module_attribute(owner, path, attr):
                    pytest.fail('invalid binding entered')
        _unchanged(owner, before)
    _unchanged(owner, before)


def test_overlapping_paths_compose_and_restore_each_outer_view():
    import os
    owner = ModuleType('overlapping_native_bindings')
    owner.os = os
    root_snapshot = dict(vars(os))
    path_snapshot = dict(vars(os.path))
    with pytest.MonkeyPatch.context() as scope:
        pid = object()
        patch_module_attribute(scope, owner, 'os', 'getpid', pid)
        outer = owner.os
        with mock_module_attribute(owner, 'os.path', 'realpath', autospec=True, return_value='owned') as realpath:
            middle = owner.os
            assert middle.getpid is pid
            assert middle.path.realpath('input', strict=True) == 'owned'
            realpath.assert_called_once_with('input', strict=True)
            with pytest.MonkeyPatch.context() as inner:
                patch_module_attribute(inner, owner, 'os.path', 'isfile', object())
                assert owner.os.getpid is pid
                assert owner.os.path.realpath is realpath
            assert owner.os is middle
        assert owner.os is outer
        assert owner.os.getpid is pid
    assert owner.os is os
    _unchanged(os, root_snapshot)
    _unchanged(os.path, path_snapshot)


@pytest.mark.parametrize('style', ['monkey', 'mock'])
def test_missing_leaf_attribute_is_local_and_removed(style):
    import os
    owner = ModuleType('nested_optional_attribute_consumer')
    owner.os = os
    name = '__raptor_optional_nested_attribute__'
    assert name not in vars(os.path)
    with pytest.MonkeyPatch.context() as scope, ExitStack() as stack:
        if style == 'monkey':
            patch_module_attribute(scope, owner, 'os.path', name, 17, raising=False)
        else:
            stack.enter_context(mock_module_attribute(owner, 'os.path', name, new=17, create=True))
        assert getattr(owner.os.path, name) == 17
        assert name not in vars(os.path)
    assert owner.os is os and name not in vars(os.path)


@pytest.mark.parametrize('shape', ['flat_only', 'both', 'lazy_flat'])
@pytest.mark.parametrize('style', ['monkey', 'mock'])
@pytest.mark.parametrize('finish', ['normal', 'error', 'interrupt'])
def test_literal_dotted_import_key_keeps_priority(shape, style, finish):
    import os
    owner = ModuleType('literal_dotted_import_consumer')
    if shape != 'flat_only':
        owner.os = os
    if shape == 'lazy_flat':
        def lazy(name):
            if name == 'os.path':
                return os.path
            raise AttributeError(name)
        owner.__getattr__ = lazy
    else:
        setattr(owner, 'os.path', os.path)
    before = dict(vars(owner))
    path_before = dict(vars(os.path))
    token = object()
    try:
        with pytest.MonkeyPatch.context() as scope, ExitStack() as stack:
            if style == 'monkey':
                patch_module_attribute(scope, owner, 'os.path', 'realpath', token)
            else:
                assert stack.enter_context(mock_module_attribute(owner, 'os.path', 'realpath', new=token)) is token
            assert getattr(owner, 'os.path').realpath is token
            if shape != 'flat_only':
                assert owner.os is os and owner.os.path is os.path
            _unchanged(os.path, path_before)
            if finish == 'error':
                raise RuntimeError('owned exit')
            if finish == 'interrupt':
                raise KeyboardInterrupt('owned exit')
    except (RuntimeError, KeyboardInterrupt) as error:
        assert type(error) is {'error': RuntimeError, 'interrupt': KeyboardInterrupt}.get(finish)
    _unchanged(owner, before)
    _unchanged(os.path, path_before)


@pytest.mark.parametrize('style', ['monkey', 'mock'])
@pytest.mark.parametrize('value', [None, object()])
def test_non_module_literal_key_cannot_fall_through_to_nested_path(style, value):
    import os
    owner = ModuleType('invalid_literal_import_consumer')
    owner.os = os
    setattr(owner, 'os.path', value)
    before = dict(vars(owner))
    with pytest.MonkeyPatch.context() as scope:
        with pytest.raises(TypeError, match='must be modules'):
            if style == 'monkey':
                patch_module_attribute(scope, owner, 'os.path', 'realpath', object())
            else:
                with mock_module_attribute(owner, 'os.path', 'realpath'):
                    pytest.fail('non-module literal entered')
        _unchanged(owner, before)

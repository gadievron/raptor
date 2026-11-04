"""Fork children must not lazily import resource and risk the import lock."""
from __future__ import annotations

import ast
import inspect

import pytest

from core.sandbox import _landlock_audit, _spawn


def _check_resource_imports(source):
    tree = ast.parse(source)
    imports = [node for node in ast.walk(tree) if (
        isinstance(node, ast.Import) and any(a.name == 'resource' for a in node.names)
        or isinstance(node, ast.ImportFrom) and node.module == 'resource'
    )]
    assert all(node in tree.body for node in imports), 'lazy resource import (post-fork hazard)'
    assert len(imports) <= 1, 'duplicate resource imports'
    uses_resource = any(isinstance(node, ast.Name) and node.id == 'resource'
                        and isinstance(node.ctx, ast.Load) for node in ast.walk(tree))
    if uses_resource:
        assert imports, 'resource is used without a module-level import'


def test_resource_is_module_level_and_never_lazy():
    for mod in (_spawn, _landlock_audit):
        _check_resource_imports(inspect.getsource(mod))


@pytest.mark.parametrize('source', [
    'def child():\n    return 0\n',
    'import resource\ndef child():\n    return resource.RLIMIT_NOFILE\n',
    'import resource as limits\ndef child():\n    return limits.RLIMIT_NOFILE\n',
    'from resource import RLIMIT_NOFILE\n',
])
def test_resource_pin_accepts_unused_or_preimported_module(source):
    _check_resource_imports(source)


@pytest.mark.parametrize('source', [
    'def child():\n    import resource\n',
    'def child():\n    import resource as limits\n',
    'def child():\n    from resource import RLIMIT_NOFILE\n',
    'def child():\n    return resource.RLIMIT_NOFILE\n',
])
def test_resource_pin_rejects_lazy_or_missing_import(source):
    with pytest.raises(AssertionError):
        _check_resource_imports(source)

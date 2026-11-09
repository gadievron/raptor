"""CLI and sibling import helpers preserve borrowed interpreter paths."""

import ast
import builtins
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

import pytest

from core.testing.module_registry import module_registry_scope

ROOT = Path(__file__).resolve().parents[3]
CASES = [('core/run/tests/test_agentic_child_pass_costs.py', '_import_agentic', 'raptor_agentic'), ('core/run/tests/test_agentic_codeql_stderr_tail.py', '_import_agentic', 'raptor_agentic'), ('core/run/tests/test_agentic_default_read_budget.py', '_import_agentic', 'raptor_agentic'), ('core/run/tests/test_agentic_entrypoint_hardening.py', '_import_agentic', 'raptor_agentic'), ('core/run/tests/test_agentic_parent_death.py', '_import_agentic', 'raptor_agentic'), ('core/run/tests/test_analyze_archive_refusal.py', '_import_raptor', 'raptor'), ('core/run/tests/test_dispatcher_flag_forwarding.py', '_import_raptor', 'raptor'), ('core/run/tests/test_dispatcher_out_flag.py', '_import_raptor', 'raptor'), ('core/run/tests/test_env_direct_downgrade_banner.py', '_import_raptor', 'raptor'), ('core/run/tests/test_fuzzing_codeql_entrypoint_fixes.py', '_import_fuzzing', 'raptor_fuzzing'), ('core/run/tests/test_max_cost_usd_lifecycle_gate.py', '_import_raptor', 'raptor'), ('core/run/tests/test_positional_target_failfast.py', '_import_raptor', 'raptor'), ('packages/cve_diff/tests/unit/infra/test_service_health.py', '_load_env_twin', 'cve_env.infra')]


@lru_cache(maxsize=None)
def _code(file, name):
    tree = ast.parse((ROOT / file).read_text())
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
    node.decorator_list = []
    return compile(ast.Module(body=[node], type_ignores=[]), str(ROOT / file), 'exec')


def _paths(kind, required):
    if kind == 'tuple':
        return ('caller',)
    if kind == 'duplicate':
        return [str(required), 'caller', str(required)]
    return ['caller']


def _cases():
    for file, name, target in CASES:
        for kind in ('missing', 'duplicate', 'tuple'):
            for mode in ('normal', 'import_error', 'import_interrupt', 'publication_error', 'publication_interrupt'):
                yield pytest.param(file, name, target, kind, mode, False,
                                   id=f'{Path(file).stem}-{kind}-{mode}')
            yield pytest.param(file, name, target, kind, 'normal', True,
                               id=f'{Path(file).stem}-{kind}-warm')


@pytest.mark.parametrize('file,name,target,kind,mode,warm', list(_cases()))
def test_import_helper_retains_caller_path(file, name, target, kind, mode, warm, monkeypatch):
    required = ROOT / 'packages/cve_env' if target == 'cve_env.infra' else ROOT
    borrowed = _paths(kind, required)
    contents = tuple(borrowed)
    result = ModuleType(target + '.owned_result')
    imported = ModuleType(target)
    if target == 'cve_env.infra':
        imported.service_health = result
    else:
        result = imported
    failure = KeyboardInterrupt('owned import interruption') if mode.endswith('interrupt') else ImportError('owned import failure')
    published, reached = [], []

    @contextmanager
    def object_scope(owner, attribute, value):
        with patch.object(owner, attribute, value):
            published.append(attribute)
            assert owner is sys and attribute == 'path'
            assert sys.path is not borrowed
            if mode.startswith('publication_'):
                raise failure
            yield

    def importing(module, globals=None, locals=None, fromlist=(), level=0):
        if module == 'unittest.mock':
            return SimpleNamespace(patch=SimpleNamespace(object=object_scope))
        if module == target:
            reached.append(module)
            assert sys.path is not borrowed
            assert warm or str(required) in sys.path
            assert tuple(borrowed) == contents
            sys.path.append('owned-import-effect')
            if mode.startswith('import_'):
                raise failure
            return imported
        return builtins.__import__(module, globals, locals, fromlist, level)

    namespace = {'__file__': str(ROOT / file), '__name__': 'owned_import_helper',
                 '_RAPTOR_ROOT': ROOT, 'sys': sys, 'pytest': pytest,
                 '__builtins__': {**vars(builtins), '__import__': importing}}
    exec(_code(file, name), namespace)
    with module_registry_scope(target) as modules, monkeypatch.context() as body:
        if warm:
            modules[target] = imported
        else:
            modules.pop(target, None)
        body.setattr(sys, 'path', borrowed)
        if mode == 'normal':
            assert namespace[name]() is result
        else:
            with pytest.raises(type(failure)) as caught:
                namespace[name]()
            assert caught.value is failure
        assert published == ['path']
        assert bool(reached) is (not mode.startswith('publication_'))
        assert sys.path is borrowed and tuple(borrowed) == contents


@pytest.mark.parametrize('kind', ['missing', 'duplicate', 'tuple'])
@pytest.mark.parametrize('mode', ['normal', 'error', 'interrupt'])
def test_egress_collection_bootstrap_retains_path(kind, mode, monkeypatch):
    file = 'core/llm/tests/test_egress.py'
    body = []
    for node in ast.parse((ROOT / file).read_text()).body:
        body.append(node)
        if any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
               and ast.unparse(n.func) == 'sys.path.insert' for n in ast.walk(node)):
            break
    else:
        pytest.fail('bootstrap path setup disappeared without updating the ownership check')
    body.append(ast.Import(names=[ast.alias(name='_owned_bootstrap_seam')]))
    tree = ast.fix_missing_locations(ast.Module(body=body, type_ignores=[]))
    borrowed = _paths(kind, ROOT)
    contents = tuple(borrowed)
    reached = []
    failure = KeyboardInterrupt('owned bootstrap interruption') if mode == 'interrupt' else ImportError('owned bootstrap failure')

    def importing(name, globals=None, locals=None, fromlist=(), level=0):
        if name == '_owned_bootstrap_seam':
            reached.append(True)
            assert sys.path is borrowed and tuple(borrowed) == contents
            if mode != 'normal':
                raise failure
            return ModuleType(name)
        return builtins.__import__(name, globals, locals, fromlist, level)

    namespace = {'__file__': str(ROOT / file), '__name__': 'owned_bootstrap_module',
                 '__builtins__': {**vars(builtins), '__import__': importing}}
    with monkeypatch.context() as body_patch:
        body_patch.setattr(sys, 'path', borrowed)
        if mode == 'normal':
            exec(compile(tree, str(ROOT / file), 'exec'), namespace)
        else:
            with pytest.raises(type(failure)) as caught:
                exec(compile(tree, str(ROOT / file), 'exec'), namespace)
            assert caught.value is failure
        assert reached == [True]
        assert sys.path is borrowed and tuple(borrowed) == contents

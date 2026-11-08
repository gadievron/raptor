"""Database and span fixtures preserve borrowed cache bindings and statistics."""
import ast
import builtins
from contextlib import contextmanager
import copy
import functools
import importlib
from pathlib import Path
from types import FunctionType, ModuleType, SimpleNamespace
import zipfile

import pytest
from core.testing.module_state import isolated_module_state

_ROOT = Path(__file__).resolve().parents[3]
_SITES = [
    ('packages/llm_analysis/tests/test_dataflow_validation.py', 'packages.llm_analysis.dataflow_validation', '_owned_database_memos', ('_db_source_cache', '_db_source_cache_chars', '_db_indexed_files', '_db_callable_inventory')),
    ('packages/llm_analysis/tests/test_e2e_iris.py', 'packages.llm_analysis.dataflow_validation', '_owned_database_memos', ('_db_source_cache', '_db_source_cache_chars', '_db_indexed_files', '_db_callable_inventory')),
    ('core/dataflow/tests/test_structural_validator.py', 'core.dataflow.structural_validator', '_owned_function_span_memo', ('_extract_functions_cached',)),
]


def _prepare(row, tmp_path, warm):
    real = importlib.import_module(row[1])
    owner = ModuleType(real.__name__)
    vars(owner).update(vars(real))
    wrappers = row[3][2:] if row[2] == '_owned_database_memos' else row[3]
    for name in wrappers:
        original = getattr(real, name)
        body = FunctionType(original.__wrapped__.__code__, vars(owner), argdefs=original.__wrapped__.__defaults__)
        body.__kwdefaults__ = original.__wrapped__.__kwdefaults__
        setattr(owner, name, functools.lru_cache(**original.cache_parameters())(body))
    if row[2] == '_owned_database_memos':
        owner._db_source_cache = {}
        owner._db_source_cache_chars = 0
        # No callable probe exists for this test-owned language. Preserve the
        # real inventory function's unavailable -> None contract without CLI.
        owner._layer3_probe_path = lambda language: None
        for name in ('_read_db_source', '_read_db_source_uncached', '_db_source_cache_clear'):
            original = getattr(real, name)
            clone = FunctionType(original.__code__, vars(owner), argdefs=original.__defaults__)
            clone.__kwdefaults__ = original.__kwdefaults__
            setattr(owner, name, clone)
        owner._read_db_source.cache_clear = owner._db_source_cache_clear
        with zipfile.ZipFile(tmp_path / 'src.zip', 'w') as archive:
            archive.writestr('repo/owned.py', 'def owned(value):\n    return value\n')
    if warm:
        for _ in range(3):
            _consume(row, owner, tmp_path)
    return owner


def _consume(row, owner, tmp_path):
    if row[2] == '_owned_database_memos':
        assert owner._db_indexed_files(tmp_path) == frozenset({'repo/owned.py'})
        assert owner._db_callable_inventory(tmp_path, 'owned-unsupported') is None
        assert 'def owned' in owner._read_db_source(tmp_path, 'repo/owned.py')
        assert owner._db_source_cache_chars == len('def owned(value):\n    return value\n')
    else:
        result = owner._extract_functions_cached('python', 'def owned(value):\n    return value\n')
        assert result and result[0].name == 'owned'


def _cases():
    for index, row in enumerate(_SITES):
        for warm in (False, True):
            for mode in ('normal', 'body_error', 'body_interrupt'):
                yield pytest.param(index, warm, mode, None, id=f'{index}-{warm}-{mode}')
            for name in row[3]:
                for mode in ('setup_error', 'setup_interrupt'):
                    yield pytest.param(index, warm, mode, name, id=f'{index}-{warm}-{mode}-{name}')


@pytest.mark.parametrize('index,warm,mode,fault_field', list(_cases()))
def test_actual_draft_fixture_restores_database_and_span_state(index, warm, mode, fault_field, tmp_path):
    row = _SITES[index]
    owner = _prepare(row, tmp_path, warm)
    borrowed = {name: getattr(owner, name) for name in row[3]}
    saved = {name: value.cache_info() if hasattr(value, 'cache_info') else copy.deepcopy(value)
             for name, value in borrowed.items()}
    failure = KeyboardInterrupt('owned interruption') if mode.endswith('interrupt') else RuntimeError('owned failure')
    published = []

    class Patcher(pytest.MonkeyPatch):
        def setattr(self, obj, name, value, *args, **kwargs):
            super().setattr(obj, name, value, *args, **kwargs)
            if obj is owner:
                published.append(name)
                if mode.startswith('setup_') and name == fault_field:
                    raise failure

    original = isolated_module_state.__wrapped__
    clone = FunctionType(original.__code__, {**original.__globals__, 'pytest': SimpleNamespace(MonkeyPatch=Patcher)}, argdefs=original.__defaults__)
    clone.__kwdefaults__ = original.__kwdefaults__
    helper = contextmanager(clone)
    def importing(name, globals=None, locals=None, fromlist=(), level=0):
        if name == row[1].rsplit('.', 1)[0]:
            return SimpleNamespace(**{row[1].rsplit('.', 1)[1]: owner})
        if name == 'core.testing.module_state':
            return SimpleNamespace(isolated_module_state=helper)
        return builtins.__import__(name, globals, locals, fromlist, level)
    namespace = {'__builtins__': {**vars(builtins), '__import__': importing}}
    node = next(n for n in ast.parse((_ROOT / row[0]).read_text()).body if isinstance(n, ast.FunctionDef) and n.name == row[2])
    node.decorator_list = []
    exec(compile(ast.Module(body=[node], type_ignores=[]), row[0], 'exec'), namespace)
    reached = []
    def execute():
        patch = Patcher()
        fixture = namespace[row[2]](patch)
        try:
            next(fixture)
            reached.append(True)
            for name in row[3]:
                if hasattr(borrowed[name], 'cache_info') or isinstance(borrowed[name], dict):
                    assert getattr(owner, name) is not borrowed[name]
                if hasattr(borrowed[name], 'cache_parameters'):
                    assert getattr(owner, name).cache_parameters() == borrowed[name].cache_parameters()
                    assert getattr(owner, name).cache_info().currsize == 0
            _consume(row, owner, tmp_path)
            # Native tests override these cache consumers. Undo that patch
            # while the fixture still owns the private module bindings.
            wrapper = row[3][-1]
            patch.setattr(owner, wrapper, lambda *args: None)
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
    for name, value in borrowed.items():
        assert getattr(owner, name) is value
        actual = value.cache_info() if hasattr(value, 'cache_info') else value
        assert actual == saved[name]

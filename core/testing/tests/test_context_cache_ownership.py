"""Context and audit fixtures preserve borrowed cache bindings."""

import ast
import builtins
from collections import OrderedDict
from contextlib import contextmanager
import copy
import importlib
import inspect
import json
from pathlib import Path
import threading
from types import FunctionType, ModuleType, SimpleNamespace

import pytest

from core.testing.module_state import isolated_module_state

_ROOT = Path(__file__).resolve().parents[3]
_SITES = json.loads((Path(__file__).parent / 'data/context_cache_sites.json').read_text())


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


def _helper(patcher):
    original = isolated_module_state.__wrapped__
    clone = FunctionType(original.__code__,
                         {**original.__globals__, 'pytest': SimpleNamespace(MonkeyPatch=patcher)},
                         argdefs=original.__defaults__)
    clone.__kwdefaults__ = original.__kwdefaults__
    return contextmanager(clone)


def _values(row, state, real):
    from core.audit.run_memo import BoundedMemo

    values = {field: {} for field in row['fields']}
    if '_kernel_file_cache' in values:
        memo = BoundedMemo(2048)
        if state == 'warm':
            memo.get_or_compute(('owned', 'driver.c'), lambda: True)
        values['_kernel_file_cache'] = memo
    elif '_pack_collection_cache' in values and state == 'warm':
        values['_pack_collection_cache'] = {'linux_kernel': (frozenset({'list_add'}), frozenset({'list_del'}))}
    elif '_UNMAPPED_CWES_LOGGED' in values:
        values['_UNMAPPED_CWES_LOGGED'] = {'CWE-0'} if state == 'warm' else set()
    elif '_TRUST_BOUNDARY_KEYS_CACHE' in values and state == 'warm':
        values['_TRUST_BOUNDARY_KEYS_CACHE'] = {'owned': frozenset({'boundary'})}
    elif '_file_lines_cache' in values:
        values.update(_file_lines_cache=OrderedDict(), _file_lines_cache_bytes=0)
        if state == 'warm':
            values.update(_file_lines_cache=OrderedDict({('owned.c', 1.0, 2): ['x\n']}), _file_lines_cache_bytes=2)
    return values


def _snapshot(value):
    from core.audit.run_memo import BoundedMemo
    if isinstance(value, BoundedMemo):
        return (copy.deepcopy(value._values), dict(value._key_locks), value.hit_count, value.miss_count)
    return copy.deepcopy(value)


def _cases():
    for row in _SITES:
        for state in ('empty', 'warm'):
            for outcome in ('normal', 'body_error', 'body_interrupt'):
                yield row, state, outcome, None
            for field in row['fields'] + (['held_alias'] if row.get('alias') else []):
                for outcome in ('setup_error', 'setup_interrupt'):
                    yield row, state, outcome, field


@pytest.mark.parametrize('row,state,outcome,fault_field', list(_cases()),
                         ids=lambda value: value['owner'] if isinstance(value, dict) else str(value))
def test_native_review_fixture_restores_borrowed_state(row, state, outcome, fault_field):
    real = importlib.import_module(row['module'])
    owner = ModuleType(real.__name__)
    vars(owner).update(vars(real))
    original = _values(row, state, real)
    for field in row['fields']:
        vars(owner).pop(field, None)
    vars(owner).update(original)
    saved = {name: _snapshot(value) for name, value in original.items()}
    lock = _Lock()
    if row['lock']:
        setattr(owner, row['lock'], lock)
    failure = KeyboardInterrupt('owned interruption') if outcome.endswith('interrupt') else RuntimeError('owned failure')
    published = []
    namespace = {row['owner']: owner}
    alias = copy.deepcopy(getattr(real, row['alias'])) if row.get('alias') else None
    if alias is not None:
        namespace[row['alias']] = alias
    alias_contents = copy.deepcopy(alias)

    class Patcher(pytest.MonkeyPatch):
        def setattr(self, obj, name, value, *args, **kwargs):
            super().setattr(obj, name, value, *args, **kwargs)
            if obj is owner and name in row['fields']:
                published.append((name, lock.held if row['lock'] else True))
                if outcome.startswith('setup_') and name == fault_field:
                    raise failure

        def setitem(self, dictionary, name, value):
            super().setitem(dictionary, name, value)
            if dictionary is namespace and outcome.startswith('setup_') and fault_field == 'held_alias':
                raise failure

    helper = _helper(Patcher)
    def importing(name, globals=None, locals=None, fromlist=(), level=0):
        if name == row['module'].rsplit('.', 1)[0]:
            return SimpleNamespace(**{row['owner']: owner})
        if name == 'core.testing.module_state':
            return SimpleNamespace(isolated_module_state=helper)
        return builtins.__import__(name, globals, locals, fromlist, level)
    namespace['__builtins__'] = {**vars(builtins), '__import__': importing}
    tree = ast.parse((_ROOT / row['file']).read_text())
    function = copy.deepcopy(next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == row['fixture']))
    function.decorator_list = []
    exec(compile(ast.Module(body=[function], type_ignores=[]), row['file'], 'exec'), namespace)
    reached = []
    def consume():
        with Patcher.context() as patcher:
            fixture = namespace[row['fixture']]
            result = fixture(monkeypatch=patcher) if 'monkeypatch' in inspect.signature(fixture).parameters else fixture()
            try:
                next(result)
                reached.append(True)
                assert not lock.held
                for field in row['fields']:
                    value = getattr(owner, field)
                    if field in original and isinstance(value, (dict, OrderedDict)):
                        assert value is not original[field]
                    if isinstance(value, (dict, set)):
                        value.clear()
                    elif hasattr(value, 'get_or_compute'):
                        value.get_or_compute(('body', 'file.c'), lambda: False)
                    elif isinstance(value, int):
                        setattr(owner, field, 999)
                if alias is not None:
                    assert namespace[row['alias']] is getattr(owner, row['alias'])
                    getattr(owner, row['alias'])['body'] = frozenset({'owned'})
                if outcome.startswith('body_'):
                    raise failure
            finally:
                result.close()
    if outcome == 'normal':
        consume()
    else:
        with pytest.raises(type(failure)) as caught:
            consume()
        assert caught.value is failure
    assert bool(reached) is (not outcome.startswith('setup_'))
    for field in row['fields']:
        if field in original:
            assert getattr(owner, field) is original[field]
            assert _snapshot(original[field]) == saved[field]
        else:
            assert field not in vars(owner)
    assert published and all(held for _, held in published)
    if alias is not None:
        assert namespace[row['alias']] is alias
        assert alias == alias_contents
    if row['lock']:
        assert not lock.held
        assert lock.acquisitions >= 2

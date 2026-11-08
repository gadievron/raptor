"""Header, detector and parser fixtures preserve borrowed cache bindings."""

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
_SITES = json.loads((Path(__file__).parent / 'data/parse_cache_sites.json').read_text())


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

    field = row['fields'][0]
    if field == '_header_cache':
        memo = BoundedMemo(16)
        if state == 'warm':
            memo.get_or_compute(('owned', 1), lambda: [Path('owned.h')])
        return {field: memo}
    if field == '_PARSE_CACHE':
        if state == 'empty':
            return {field: OrderedDict()}
        with isolated_module_state(real, {field: OrderedDict()}, lock=real._PARSE_CACHE_LOCK):
            parsed = real._parse_file('owned.c', 'int owned(void) { return 1; }')
            if parsed is None:
                pytest.skip('C grammar required for a production parse-cache payload')
            return {field: OrderedDict(real._PARSE_CACHE)}
    if field == '_module_fp_memo':
        return {field: {('core.audit.context',): 'owned-fingerprint'} if state == 'warm' else {}}
    return {field: {('owned', None, None): {'owned.c': {}}} if state == 'warm' else {}}


def _snapshot(value):
    from core.audit.run_memo import BoundedMemo
    if isinstance(value, BoundedMemo):
        return (copy.deepcopy(value._values), dict(value._key_locks), value.hit_count, value.miss_count)
    if isinstance(value, OrderedDict):
        return [(key, id(payload[0]), payload[1:]) for key, payload in value.items()]
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

"""Audit, lexical and prompt fixtures restore borrowed cache bindings."""

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
_SITES = json.loads((Path(__file__).parent / 'data/review_cache_sites.json').read_text())


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
    values = {field: {} for field in row['fields']}
    if row['owner'] == 'orchestrator':
        values.update(_file_lines_cache=OrderedDict(), _file_lines_cache_bytes=0)
        if state == 'warm':
            values.update(_sink_guard_cache={'owned': 'guard'},
                          _parse_wrapper_cache={'owned': frozenset({'wrapper'})},
                          _line_end_cache={('owned', 'c', 'function'): 2},
                          _file_lines_cache=OrderedDict({('owned.c', 1.0, 2): ['x\n']}),
                          _file_lines_cache_bytes=2)
    elif row['owner'] == 'return_contracts' and state == 'warm':
        values.update(_IRIS_SPEC_CACHE={'owned': ((1, 2), [])},
                      _ANNOTATION_SCAN_CACHE={'owned': ((), [])})
    elif row['owner'] == 'refutation' and state == 'warm':
        values['_threading_seen_cache'] = {('owned', 1): real._VetoScan(False, True)}
    elif row['owner'] == 'analysis' and state == 'warm':
        values['_THREAT_MODEL_BLOCK_CACHE'] = {'owned': ()}
    elif row['owner'] == 'lexical_view':
        values.update(_memo=OrderedDict(), NONCODE_NODE_MODES=copy.deepcopy(real.NONCODE_NODE_MODES))
        if state == 'warm':
            values.update(_VALIDATED={'javascript': None},
                          _memo=OrderedDict({('javascript', 1, 'source'): '      '}))
    return values


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
    saved = copy.deepcopy(original)
    lock = _Lock()
    if row['lock']:
        setattr(owner, row['lock'], lock)
    failure = KeyboardInterrupt('owned interruption') if outcome.endswith('interrupt') else RuntimeError('owned failure')
    published = []
    namespace = {row['owner']: owner}
    alias = copy.deepcopy(real.NONCODE_NODE_MODES) if row.get('alias') else None
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
                    if isinstance(value, dict):
                        value.clear()
                    elif isinstance(value, int):
                        setattr(owner, field, 999)
                if alias is not None:
                    assert namespace[row['alias']] is owner.NONCODE_NODE_MODES
                    owner.NONCODE_NODE_MODES['javascript'] = {'owned': 'all'}
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
            assert original[field] == saved[field]
        else:
            assert field not in vars(owner)
    assert published and all(held for _, held in published)
    if alias is not None:
        assert namespace[row['alias']] is alias
        assert alias == alias_contents
    if row['lock']:
        assert not lock.held
        assert lock.acquisitions >= 2

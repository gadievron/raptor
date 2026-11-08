"""Supply-chain fixtures preserve borrowed caches and planted-data boundaries."""

import ast
from contextlib import contextmanager, nullcontext
import copy
from functools import lru_cache
import importlib
import inspect
import json
from pathlib import Path
import re
import shutil
import threading
from types import FunctionType, ModuleType, SimpleNamespace

import pytest

from core.testing.module_state import isolated_module_state

_ROOT = Path(__file__).resolve().parents[3]
_SITES = json.loads((Path(__file__).parent / 'data/supply_chain_cache_sites.json').read_text())
_BASELINE = None


@lru_cache(maxsize=None)
def _tree(file):
    return ast.parse(((_BASELINE or _ROOT) / file).read_text())


def _function(file, name, namespace):
    function = copy.deepcopy(next(n for n in ast.walk(_tree(file)) if isinstance(n, ast.FunctionDef) and n.name == name))
    function.decorator_list = []
    exec(compile(ast.Module(body=[function], type_ignores=[]), file, 'exec'), namespace)
    return namespace[name]


@contextmanager
def _fixture(function):
    result = function()
    if inspect.isgenerator(result):
        try:
            yield next(result)
        finally:
            result.close()
    else:
        yield result


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


def _owner(row):
    real = importlib.import_module('packages.sca.supply_chain.' + row['owner'])
    owner = ModuleType(real.__name__)
    vars(owner).update(vars(real))
    if row.get('lock'):
        owner._META_CACHE_LOCK = _Lock()
        owner._reset_meta_cache_for_tests = FunctionType(real._reset_meta_cache_for_tests.__code__, vars(owner))
    return real, owner


def _cache(row, state, real):
    if row['owner'] == 'registry_metadata':
        return {} if state == 'empty' else {('npm', 'owned'): None if state == 'cold' else real._Meta()}
    if state == 'cold':
        return None
    if state == 'empty':
        return [] if row['owner'] == 'exfil_destinations' else {}
    with isolated_module_state(real, {row['field']: None}):
        return getattr(real, row['loader'])()


def _helper(patcher):
    # Only this consumer's helper sees the injected patcher. Other pytest
    # users and module-state owners retain their original bindings.
    function = isolated_module_state.__wrapped__
    clone = FunctionType(function.__code__, {**function.__globals__, 'pytest': SimpleNamespace(MonkeyPatch=patcher)}, argdefs=function.__defaults__)
    clone.__kwdefaults__ = function.__kwdefaults__
    return contextmanager(clone)


@pytest.mark.parametrize('row', _SITES, ids=lambda row: row['file'])
@pytest.mark.parametrize('state', ['cold', 'empty', 'warm'])
@pytest.mark.parametrize('outcome', ['normal', 'body_error', 'body_interrupt', 'setup_error', 'setup_interrupt'])
def test_native_cache_fixture_preserves_borrowed_state(row, state, outcome):
    real, owner = _owner(row)
    field = row['field']
    previous = _cache(row, state, real)
    setattr(owner, field, previous)
    contents = previous.copy() if previous is not None else None
    failure = KeyboardInterrupt('owned interruption') if outcome.endswith('interrupt') else RuntimeError('owned failure')
    publications = []

    class Patcher(pytest.MonkeyPatch):
        def setattr(self, obj, name, value, *args, **kwargs):
            super().setattr(obj, name, value, *args, **kwargs)
            if obj is owner and name == field:
                publications.append(owner._META_CACHE_LOCK.held if row.get('lock') else True)
                if outcome.startswith('setup_'):
                    raise failure

    helper = _helper(Patcher)
    def importing(name, globals=None, locals=None, fromlist=(), level=0):
        if name == 'packages.sca.supply_chain':
            return SimpleNamespace(**{row['owner']: owner})
        if name == 'packages.sca.supply_chain.registry_metadata':
            return owner
        if name == 'core.testing.module_state':
            return SimpleNamespace(isolated_module_state=helper)
        return __import__(name, globals, locals, fromlist, level)

    namespace = dict(exfil_destinations=owner, isolated_module_state=helper,
                     __builtins__={**vars(__import__('builtins')), '__import__': importing})
    name = row['fixture']
    if not any(isinstance(n, ast.FunctionDef) and n.name == name for n in ast.walk(_tree(row['file']))):
        name = row.get('legacy')
    scope = _fixture(_function(row['file'], name, namespace)) if name else nullcontext()
    admitted = []
    def consume():
        with scope:
            cache = getattr(owner, field)
            admitted.append(cache == ({} if row.get('lock') else None))
            if row.get('lock'):
                admitted.append(cache is not previous)
                with owner._META_CACHE_LOCK:
                    cache[('npm', 'owned-body')] = real._Meta()
            else:
                setattr(owner, field, _cache(row, 'warm', real))
            if outcome.startswith('body_'):
                raise failure
    if outcome == 'normal':
        consume()
    else:
        with pytest.raises(type(failure)) as caught:
            consume()
        assert caught.value is failure
    if not outcome.startswith('setup_'):
        assert admitted and all(admitted)
    assert getattr(owner, field) is previous
    assert previous == contents
    assert publications and all(publications)
    if row.get('lock'):
        assert not owner._META_CACHE_LOCK.held
        assert owner._META_CACHE_LOCK.acquisitions >= 2


def _loader_owner(name, field):
    real = importlib.import_module('packages.sca.supply_chain.' + name)
    owner = ModuleType(real.__name__)
    vars(owner).update(vars(real))
    loader = '_load_rules' if name == 'exfil_destinations' else '_load_allowlist'
    setattr(owner, loader, FunctionType(getattr(real, loader).__code__, vars(owner)))
    return real, owner, loader


@pytest.mark.parametrize('kind', ['exfil', 'binary'])
@pytest.mark.parametrize('state', ['cold', 'empty', 'warm'])
@pytest.mark.parametrize('outcome', ['normal', 'error', 'interrupt'])
def test_native_planted_census_preserves_cache_and_data_path(kind, state, outcome, tmp_path):
    exfil_real, exfil, exfil_loader = _loader_owner('exfil_destinations', '_RULES_CACHE')
    binary_real, binary, binary_loader = _loader_owner('binary_in_package', '_ALLOWLIST')
    exfil_row = next(row for row in _SITES if row['owner'] == 'exfil_destinations')
    binary_row = next(row for row in _SITES if row['owner'] == 'binary_in_package')
    exfil._RULES_CACHE = _cache(exfil_row, state, exfil_real)
    binary._ALLOWLIST = _cache(binary_row, state, binary_real)
    previous = exfil._RULES_CACHE, binary._ALLOWLIST, exfil._DATA_FILE, binary._allowlist_path
    failure = RuntimeError('owned loader failed') if outcome == 'error' else KeyboardInterrupt('owned loader interrupted')
    owner, loader = (exfil, exfil_loader) if kind == 'exfil' else (binary, binary_loader)
    actual = getattr(owner, loader)
    reached = []
    def loading():
        path = exfil._DATA_FILE if kind == 'exfil' else binary._allowlist_path()
        assert path.is_relative_to(tmp_path)
        assert 'planted-quadratic' in path.read_text()
        result = actual()
        reached.append(path)
        if outcome != 'normal':
            raise failure
        return result
    setattr(owner, loader, loading)
    native = importlib.import_module('packages.sca.supply_chain.tests.test_pattern_data_census')
    namespace = dict(_exfil=exfil, _bip=binary, shutil=shutil, json=json,
                     _census=native._census, isolated_module_state=isolated_module_state, re=re)
    file = 'packages/sca/supply_chain/tests/test_pattern_data_census.py'
    _function(file, '_sca_data_file_members', namespace)
    name = ('test_sca_data_arm_detects_a_planted_exfil_member' if kind == 'exfil'
            else 'test_sca_data_arm_detects_a_planted_name_suffix_member')
    function = _function(file, name, namespace)
    with pytest.MonkeyPatch.context() as patcher:
        kwargs = {'tmp_path': tmp_path}
        if 'monkeypatch' in inspect.signature(function).parameters:
            kwargs['monkeypatch'] = patcher
        if outcome == 'normal':
            function(**kwargs)
        else:
            with pytest.raises(type(failure)) as caught:
                function(**kwargs)
            assert caught.value is failure
    assert reached
    assert exfil._RULES_CACHE is previous[0] and binary._ALLOWLIST is previous[1]
    assert exfil._DATA_FILE is previous[2] and binary._allowlist_path is previous[3]

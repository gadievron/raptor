"""Reachability tests retain warm caller indexes and exercise private LRUs."""

from collections import OrderedDict
import importlib

import pytest

from core.analysis import reachability as reach
from core.testing.reachability_state import _CACHE_POLICIES, isolated_reachability_caches


NATIVE = ('core.analysis.tests.test_reach_cache', 'core.analysis.tests.test_reach_witness', 'core.analysis.tests.test_reachability', 'core.analysis.tests.test_reachability_adjacency', 'core.analysis.tests.test_reachability_c_implementation_includes', 'core.analysis.tests.test_reachability_closure', 'core.analysis.tests.test_reachability_entry_and_samefile', 'core.analysis.tests.test_reachability_gates', 'core.inventory.tests.test_call_graph_cpp', 'core.inventory.tests.test_call_graph_go', 'core.inventory.tests.test_call_graph_java', 'core.inventory.tests.test_call_graph_javascript', 'packages.sca.reachability.tests.test_called_in_dead_code_e2e')


def _build_indexes(inventory):
    reach._get_function_called_index(inventory)
    reach._get_bo_item_index(inventory)
    reach._get_or_build_index(inventory, exclude_test_files=False)
    reach._entry_functions(inventory)
    reach._files_by_path(inventory)
    reach._entry_reachable_set(inventory)


def _borrowed(monkeypatch, warm):
    # Obtain real cache entries, including their inventory identity guards.
    with isolated_reachability_caches():
        if warm:
            for _ in range(2):
                _build_indexes({'files': []})
        caches = {name: OrderedDict(getattr(reach, name)) for name, _ in _CACHE_POLICIES}
    values = {}
    for name, capacity in _CACHE_POLICIES:
        value = caches[name]
        monkeypatch.setattr(reach, name, value)
        values[name] = (value, list(value.items()), getattr(reach, capacity),
                        getattr(reach, name + "_LOCK"))
    return values


def _assert_retained(values):
    for name, capacity in _CACHE_POLICIES:
        value, contents, limit, lock = values[name]
        assert getattr(reach, name) is value
        assert list(value.items()) == contents
        assert getattr(reach, capacity) == limit
        assert getattr(reach, name + "_LOCK") is lock


def _finish(outcome):
    if outcome == 'error':
        raise RuntimeError('native body failed')
    if outcome == 'interrupt':
        raise KeyboardInterrupt('native body interrupted')


@pytest.mark.parametrize('module', NATIVE)
@pytest.mark.parametrize('warm', [False, True], ids=['cold-caller', 'warm-caller'])
@pytest.mark.parametrize('outcome', ['normal', 'error', 'interrupt'])
def test_native_fixture_retains_indexes(module, warm, outcome, monkeypatch):
    native = importlib.import_module(module if module.startswith(('core.','packages.')) else 'core.analysis.tests.' + module)
    values = _borrowed(monkeypatch, warm)
    body = pytest.MonkeyPatch()
    generator = native._owned_reachability_caches.__wrapped__(body)
    try:
        next(generator)
        for name, capacity in _CACHE_POLICIES:
            assert getattr(reach, name) is not values[name][0]
            assert isinstance(getattr(reach, name), OrderedDict)
            assert not getattr(reach, name)
            # A later body override must unwind before the caller is restored.
            body.setattr(reach, name, OrderedDict(((3, object()),)))
            body.setattr(reach, capacity, 1)
        _finish(outcome)
    except (RuntimeError, KeyboardInterrupt) as error:
        assert type(error) is {'error': RuntimeError, 'interrupt': KeyboardInterrupt}[outcome]
    finally:
        generator.close()
        body.undo()
    _assert_retained(values)


@pytest.mark.parametrize('cache', [name for name, _ in _CACHE_POLICIES])
@pytest.mark.parametrize('outcome', ['normal', 'error', 'interrupt'])
def test_real_index_build_preserves_caller(cache, outcome, monkeypatch):
    values = _borrowed(monkeypatch, True)
    inventory = {'files': []}
    with pytest.raises((RuntimeError, KeyboardInterrupt)) if outcome != 'normal' else _no_error():
        with isolated_reachability_caches():
            builders = {
                '_FN_CALLED_INDEX_CACHE': lambda: reach._get_function_called_index(inventory),
                '_BO_ITEM_INDEX_CACHE': lambda: reach._get_bo_item_index(inventory),
                '_INDEX_CACHE': lambda: reach._get_or_build_index(inventory, exclude_test_files=False),
                '_ENTRY_SET_CACHE': lambda: reach._entry_functions(inventory),
                '_FILES_BY_PATH_CACHE': lambda: reach._files_by_path(inventory),
                '_ENTRY_REACHABLE_CACHE': lambda: reach._entry_reachable_set(inventory),
            }
            builders[cache]()
            assert id(inventory) in getattr(reach, cache)
            _finish(outcome)
    _assert_retained(values)


def _no_error():
    from contextlib import nullcontext
    return nullcontext()


@pytest.mark.parametrize('outcome', ['normal', 'error', 'interrupt'])
@pytest.mark.parametrize('module,method', [
    ('test_reachability', 'test_attribute_chain_call_resolves'),
    ('test_reachability_entry_and_samefile', 'test_files_by_path_cache_evicts_least_recently_used'),
])
def test_native_resolver_and_eviction_retain_caller(module, method, outcome, monkeypatch):
    native = importlib.import_module(module if module.startswith(('core.','packages.')) else 'core.analysis.tests.' + module)
    values = _borrowed(monkeypatch, True)
    body = pytest.MonkeyPatch()
    generator = native._owned_reachability_caches.__wrapped__(body)
    try:
        next(generator)
        getattr(native, method)()
        _finish(outcome)
    except (RuntimeError, KeyboardInterrupt) as error:
        assert type(error) is {'error': RuntimeError, 'interrupt': KeyboardInterrupt}[outcome]
    finally:
        generator.close()
        body.undo()
    _assert_retained(values)


@pytest.mark.parametrize('outcome', ['normal', 'error', 'interrupt'])
def test_probe_fixture_loading_preserves_caller_state(outcome, monkeypatch):
    from types import SimpleNamespace
    from core.sandbox import state
    from core.testing.tests import test_probe_cache_owner_state as harness

    inherited = {name: getattr(state, name) for name in harness._IMPORT_PROBE_STATE}
    fixture = SimpleNamespace(__wrapped__=lambda: None)
    module = SimpleNamespace(owned=fixture)

    def load(name):
        for field in inherited:
            setattr(state, field, False if field.endswith('_warned') else None)
        state._net_available_cache = True
        state._unshare_path_cache = '/owned/import/unshare'
        _finish(outcome)
        return module

    monkeypatch.setattr(harness, 'importlib', SimpleNamespace(import_module=load))
    try:
        loaded, _, _ = harness._fixture({'file': 'owned/native.py', 'class': None, 'fixture': 'owned'})
        assert loaded is module
    except (RuntimeError, KeyboardInterrupt) as error:
        assert type(error) is {'error': RuntimeError, 'interrupt': KeyboardInterrupt}[outcome]
    assert all(getattr(state, name) is value for name, value in inherited.items())

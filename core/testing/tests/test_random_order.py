"""The real collection hook must distinguish complete CI seeds and preserve scopes."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def shuffle_hook(pytestconfig, monkeypatch):
    root = Path(__file__).resolve().parents[3]
    plugin = pytestconfig.pluginmanager.getplugin(str(root / 'conftest.py'))
    assert plugin is not None
    monkeypatch.setattr(plugin, '_EMULATED_PLATFORM', None)

    def reorder(seed):
        monkeypatch.setattr(plugin, '_RANDOMISE_SEED_RAW', seed)
        items = [
            SimpleNamespace(
                nodeid=f'module_{module}.py::Test{cls}::test_{case}',
                get_closest_marker=lambda name: None,
            )
            for module in range(6) for cls in range(3) for case in range(6)
        ]
        plugin.pytest_collection_modifyitems(pytestconfig, items)
        return [item.nodeid for item in items]

    return reorder


def test_ci_iterations_produce_distinct_reproducible_orders(shuffle_hook):
    seeds = [f'41752054863-{iteration}' for iteration in (1, 2, 3)]
    orders = [shuffle_hook(seed) for seed in seeds]
    assert len({tuple(order) for order in orders}) == 3
    assert shuffle_hook(seeds[0]) == orders[0]
    assert all(set(order) == set(orders[0]) for order in orders)


def test_shuffle_preserves_module_and_class_contiguity(shuffle_hook):
    order = shuffle_hook('41752054863-1')
    for depth in (1, 2):
        groups = ['::'.join(node.split('::')[:depth]) for node in order]
        runs = [group for i, group in enumerate(groups) if i == 0 or group != groups[i-1]]
        assert len(runs) == len(set(groups))


def test_numeric_seed_keeps_existing_random_order_semantics(shuffle_hook):
    # "42" and "00042" are both interpreted as the same integer.
    assert shuffle_hook('42') == shuffle_hook('00042')
    assert shuffle_hook('42') != shuffle_hook('43')

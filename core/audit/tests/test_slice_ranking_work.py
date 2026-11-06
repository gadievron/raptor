"""Assembly-stable ranking inputs are reused without sharing slice-owned lists."""

from core.audit.cross_entry import slices
from core.audit.cross_entry.model import Limits
from core.audit.tests.test_slice_work_indexes import allowances, index_fixture


def test_immutable_limit_settings_are_computed_once():
    calls = []
    class CountedLimits(Limits):
        def content_settings(self):
            calls.append(self)
            return super().content_settings()

    limits = CountedLimits(graph_seconds=1000, max_slices=100)
    units, _ = slices.build_slices(index_fixture(), limits=limits)
    assert len(units) == 6
    assert calls == [limits]


def test_focus_order_is_stable_and_each_slice_owns_its_list():
    index = index_fixture()
    focus = ['unknown', 'f2', 'f0', 'f2']
    units, _ = slices.build_slices(index, limits=allowances(), focus_functions=focus)
    expected = ['f0', 'f2', 'unknown']
    assert all(unit.focus_functions == expected for unit in units)
    assert len({id(unit.focus_functions) for unit in units}) == len(units)
    units[0].focus_functions.append('consumer edit')
    assert all(unit.focus_functions == expected for unit in units[1:])
    assert focus == ['unknown', 'f2', 'f0', 'f2']
    again, _ = slices.build_slices(index, limits=allowances(), focus_functions=focus)
    assert all(unit.focus_functions == expected for unit in again)


def test_rarity_and_mutation_priorities_remain_ordered():
    index = index_fixture()
    for i, access in enumerate(index.accesses):
        access.member_path = 'rare' if i in {0, 1, 3} else 'common'
    index.accesses[3].operation = 'read'
    units, _ = slices.build_slices(index, ['f0'], limits=allowances())
    assert units[0].functions[:3] == ['f0', 'f1', 'f3']

"""Context optimizations retain previews, references, and input ordering."""

import pytest

from core.audit.struct_accessor_index import (
    AccessorRecord, CoAccessorGroup, _dedupe_accessors,
    format_co_accessor_context, get_co_accessors,
)


def test_many_locks_preserve_preview_order_and_input_list():
    entries = [('c_first', 'C'), ('a_first', 'A'), ('c_second', 'C'),
               ('d_first', 'D'), ('b_first', 'B'), ('a_second', 'A'),
               ('c_third', 'C'), ('b_second', 'B')]
    records = [AccessorRecord(name, 'x.c', 'epoch', lock) for name, lock in entries]
    before = [id(r) for r in records]
    group = CoAccessorGroup('epoch', records, lock_conflict=True)
    description = ('`epoch` accessed under different locks: '
                   'a_first, a_second (under A); b_first, b_second (under B); '
                   'c_first, c_second (under C); d_first (under D)')
    assert group.description == description
    assert format_co_accessor_context([group]) == (
        '[Struct-field co-accessor analysis]\n  - [LOCK CONFLICT] ' + description
    )
    assert group.accessors is records
    assert [id(r) for r in records] == before


def test_native_preview_counts_all_accessors_for_suffix():
    records = [AccessorRecord(f'f{i}', 'x.c', 'epoch') for i in range(7)]
    assert CoAccessorGroup('epoch', records).description == (
        '`epoch` accessed by f0, f1, f2, f3 (+3 more)'
    )


@pytest.mark.parametrize('same_file_only', [False, True, 1],
                         ids=['all-files', 'same-file', 'truthy-fallback'])
def test_group_filtering_retains_first_duplicate_references(same_file_only):
    other = AccessorRecord('other', 'x.c', 'epoch', '')
    mine = AccessorRecord('mine', 'x.c', 'epoch', 'L')
    foreign = AccessorRecord('foreign', 'y.c', 'epoch', '')
    records = [other, mine, AccessorRecord('mine', 'x.c', 'epoch', ''),
               AccessorRecord('other', 'x.c', 'epoch', 'L'), foreign]
    before = [id(r) for r in records]
    groups = get_co_accessors({'epoch': records}, 'mine', 'x.c',
                              same_file_only=same_file_only)
    expected = [mine, other] if same_file_only else [mine, other, foreign]
    assert len(groups) == 1 and groups[0].lock_conflict
    assert [id(r) for r in groups[0].accessors] == [id(r) for r in expected]
    assert [id(r) for r in records] == before


def test_iterator_description_keeps_original_consumption():
    records = [AccessorRecord(f'f{i}', 'x.c', 'epoch', 'L') for i in range(6)]
    assert CoAccessorGroup('epoch', iter(records)).description == (
        '`epoch` accessed by f0, f1, f2, f3 (+2 more)'
    )


def test_list_subclass_does_not_use_native_preview_slice():
    class Records(list):
        def __getitem__(self, key):
            if isinstance(key, slice):
                pytest.fail('Native preview sliced a custom list')
            return super().__getitem__(key)

    records = Records([AccessorRecord('first', 'x.c', 'epoch')])
    assert CoAccessorGroup('epoch', records).description == '`epoch` accessed by first'


def test_streamed_dedupe_keeps_first_record():
    first = AccessorRecord('first', 'x.c', 'epoch', 'L')
    duplicate = AccessorRecord('first', 'x.c', 'epoch', '')
    other = AccessorRecord('other', 'x.c', 'epoch', '')
    result = _dedupe_accessors(iter([first, duplicate, other]))
    assert [id(r) for r in result] == [id(first), id(other)]


def test_unlocked_preview_does_not_copy_every_function_name():
    import tracemalloc

    if tracemalloc.is_tracing():
        pytest.skip('Requires an independently owned allocation tracer')
    records = [AccessorRecord(f'f{i}', 'x.c', 'epoch') for i in range(25000)]
    group = CoAccessorGroup('epoch', records)
    try:
        tracemalloc.start()
        description = group.description
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert description.endswith('(+24996 more)')
    assert peak < 320 * 1024, f'Preview allocated {peak} bytes'

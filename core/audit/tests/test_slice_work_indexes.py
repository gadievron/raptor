"""Per-assembly indexes retain path ownership, relationship scope and call order."""

from collections import Counter

from core.audit.cross_entry import slices
from core.audit.cross_entry.model import Access, AccessIndex, Call, Function, Limits, Relation


def index_fixture(count=6):
    index = AccessIndex()
    index.coverage['complete'] = True
    index.fingerprint = 'stable-fixture'
    for i in range(count):
        fid = f'f{i}'
        source = f'void {fid}(struct state *ctx) {{ ctx->field++; }}'
        index.functions[fid] = Function(fid, 'a.c', fid, 1, 1, 0, len(source), '', source)
        index.accesses.append(Access(f'a{i}', fid, 'a.c', 1, 0, 1, 'T', 'ctx',
                                     'field', 'read_modify_write', 'ctx->field', resolution='resolved'))
        index.entries[fid] = [{'field': f'route{i}'}]
    return index


def allowances(**kwargs):
    return Limits(graph_seconds=1000, max_slices=100, source_chars=100000, **kwargs)


def test_global_collections_are_indexed_once():
    class CountedList(list):
        iterations = 0
        def __iter__(self):
            self.iterations += 1
            return super().__iter__()

    index = index_fixture()
    index.accesses = CountedList(index.accesses)
    index.relations = CountedList([Relation('T:field', 'U:other', 'resource_assignment', 'edge')])
    index.calls = CountedList([Call('f0', 'unknown', [], 1)])
    units, _ = slices.build_slices(index, limits=allowances())
    assert len(units) == len(index.functions)
    assert index.accesses.iterations == 1
    assert index.relations.iterations == 1
    assert index.calls.iterations == 1


def test_entry_searches_are_reused_but_slices_own_paths(monkeypatch):
    index = index_fixture()
    index.relations.append(Relation('f0', 'f1', 'call', 'edge'))
    original = slices.entry_paths
    searched = Counter()
    def counted(index, target, depth, parents=None):
        searched[target] += 1
        return original(index, target, depth, parents)
    monkeypatch.setattr(slices, 'entry_paths', counted)
    units, _ = slices.build_slices(index, limits=allowances())
    assert searched and all(count == 1 for count in searched.values())
    first = next(unit for unit in units if unit.entry_paths)
    first.entry_paths[0].append('consumer edit')
    assert all('consumer edit' not in path for unit in units if unit is not first for path in unit.entry_paths)
    again, _ = slices.build_slices(index, limits=allowances())
    assert all('consumer edit' not in path for unit in again for path in unit.entry_paths)


def test_unresolved_receipt_retains_global_call_order_before_cap():
    index = index_fixture()
    for i in range(70):
        index.calls.append(Call(f'f{(i*5)%6}', f'unknown{99-i}', [], i+1))
    units, _ = slices.build_slices(index, ['f0'], limits=allowances())
    assert len(units) == 1
    unit = units[0]
    expected = sorted(f'{call.caller}:{call.line}:{call.name}' for call in index.calls[:64])
    assert unit.unresolved == expected
    assert 'unresolved_edges:7' in unit.truncated


def test_resource_links_are_one_hop_and_include_unresolved_accesses():
    index = index_fixture(3)
    for i, access in enumerate(index.accesses):
        access.type_id = f'T{i}'
    index.accesses[1].resolution = 'unresolved'
    index.relations = [Relation('T0:field', 'T1:field', 'resource_assignment', 'first'),
                       Relation('T1:field', 'T2:field', 'resource_assignment', 'second')]
    units, _ = slices.build_slices(index, ['f0'], limits=allowances())
    assert units[0].functions == ['f0', 'f1']
    assert 'cross_type_resource_assignment' in units[0].reasons
    assert 'f2' not in units[0].evidence_candidates


def test_assembly_does_not_modify_index():
    index = index_fixture()
    before = index.to_dict()
    slices.build_slices(index, limits=allowances())
    assert index.to_dict() == before

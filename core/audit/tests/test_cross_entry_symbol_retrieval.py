"""One-round symbol grouping preserves demand-retrieval decisions and freshness."""

import pytest

from core.audit.cross_entry import study_engine
from core.audit.cross_entry.model import AccessIndex, Function


class Counted(dict):
    scans = 0

    def values(self):
        self.scans += 1
        return super().values()


def function(fid, name):
    return Function(fid, 'a.c', name, 1, 1, 0, 1, 'hash', 'void f(void){}')


@pytest.fixture
def index():
    result = AccessIndex()
    result.functions = Counted({f'f{i}': function(f'f{i}', f'symbol{i}') for i in range(100)})
    result.functions['ambiguous-a'] = function('ambiguous-a', 'ambiguous')
    result.functions['ambiguous-b'] = function('ambiguous-b', 'ambiguous')
    return result


def test_grouping_preserves_duplicates_ambiguity_and_existing_functions(index):
    names = ['symbol1', 'symbol2', 'missing', 'symbol1', 'ambiguous']
    before = names.copy()
    assert study_engine._retrieval_candidates(index, names, ['f2']) == ['f1', 'f1']
    assert index.functions.scans == 1
    assert names == before


def test_small_requests_keep_the_direct_scan(index):
    assert study_engine._retrieval_candidates(index, ['symbol1', 'missing', 'symbol2'], []) == ['f1', 'f2']
    assert index.functions.scans == 3


def test_no_requested_names_does_not_scan_functions(index):
    assert study_engine._retrieval_candidates(index, [], []) == []
    assert index.functions.scans == 0


def test_duplicate_definition_ids_are_still_ambiguous(index):
    index.functions['ambiguous-a'].id = 'same-id'
    index.functions['ambiguous-b'].id = 'same-id'
    assert study_engine._retrieval_candidates(index, ['ambiguous', 'x', 'y', 'z'], []) == []


def test_each_round_observes_new_and_removed_definitions(index):
    names = ['symbol1', 'x', 'y', 'z']
    assert study_engine._retrieval_candidates(index, names, []) == ['f1']
    index.functions['new'] = function('new', 'symbol1')
    assert study_engine._retrieval_candidates(index, names, []) == []
    del index.functions['f1']
    assert study_engine._retrieval_candidates(index, names, []) == ['new']


class AdaptedName(str):
    __hash__ = None

    def __len__(self):
        pytest.fail('adapter length was probed instead of using the legacy equality scan')


@pytest.mark.parametrize('name,expected', [
    pytest.param(AdaptedName('special'), ['special-id'], id='unhashable-string-adapter'),
    pytest.param(None, [], id='legacy-null'),
    pytest.param(['special'], [], id='legacy-list'),
])
def test_non_native_function_names_keep_legacy_equality_behaviour(index, name, expected):
    index.functions['special-id'] = function('special-id', name)
    assert study_engine._retrieval_candidates(index, ['special', 'x', 'y', 'z'], []) == expected


def test_non_native_requested_names_keep_legacy_equality_behaviour(index):
    names = [AdaptedName('symbol1'), 'x', 'y', 'z']
    assert study_engine._retrieval_candidates(index, names, []) == ['f1']


def test_long_unrelated_names_do_not_change_matches(index):
    index.functions['large'] = function('large', 'oversized_' + 'x' * 100000)
    assert study_engine._retrieval_candidates(index, ['symbol1', 'x', 'y', 'z'], []) == ['f1']


def test_grouped_retrieval_keeps_id_order_cap_and_cached_reuse(tmp_path):
    from core.audit.callsite_consistency import parse_source_cached
    if parse_source_cached('probe.c', 'int f(void){return 0;}')[0] is None:
        pytest.skip('requires tree-sitter C grammar')
    from core.audit.cross_entry import build_access_index, build_slices
    from core.audit.cross_entry.study import run_studies
    from core.audit.tests.test_cross_entry import Client, fn, sources
    source = sources()
    source['helpers.c'] = ''.join(f'int helper{i}(void){{return {i};}}\n' for i in range(6))
    source['duplicate-a.c'] = 'int ambiguous(void){return 1;}'
    source['duplicate-b.c'] = 'int ambiguous(void){return 2;}'
    source['padding.c'] = ''.join(f'int unrelated{i}(void){{return {i};}}\n' for i in range(100))
    actual = build_access_index(source)
    unit = build_slices(actual, ['reader.c:get'])[0][0]
    expected = sorted(fn(actual, f'helper{i}') for i in range(6))[:4]
    actual.functions = Counted(actual.functions)
    needed = [f'helper{i}' for i in range(6)] + ['ambiguous', 'get', '../../secret']
    client = Client([
        {'facts': [], 'witnesses': [], 'needed_symbols': needed},
        {'facts': [], 'witnesses': [], 'needed_symbols': []},
    ])
    result = run_studies(actual, [unit], client, out_dir=tmp_path)[unit.id]
    assert result['status'] == 'complete'
    assert result['retrieved_functions'] == expected
    assert result['functions'][0] == unit.consumer
    assert actual.functions.scans == 1
    assert len(client.calls) == 2
    cached = run_studies(actual, [unit], client, out_dir=tmp_path)[unit.id]
    assert cached['cache_hit']
    assert len(client.calls) == 2

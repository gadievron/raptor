"""Run-owned query reuse preserves sentinel findings and adapter operations."""

import pytest

from core.audit import sentinel_collapse as mod


def ambiguous(value='None'):
    return (f'def fetch():\n    try:\n        return {value}\n'
            f'    except Exception:\n        return {value}\n')


def caller(coerce=True):
    end = 'return values or []' if coerce else 'return values'
    return '# padding\n' * 700 + f'\ndef consume():\n    values = fetch()\n    {end}\n'


def graph(count, *, name='consume', callee='fetch'):
    return {'calls': [{'caller': name, 'chain': [callee]} for _ in range(count)]}


@pytest.fixture
def memos(monkeypatch):
    created = []
    actual = mod.BoundedMemo

    def observed(limit):
        memo = actual(limit)
        created.append((limit, memo))
        return memo

    monkeypatch.setattr(mod, 'BoundedMemo', observed)
    return created


@pytest.mark.parametrize('coerce', [True, False], ids=['positive', 'negative'])
def test_repeated_native_queries_reuse_facts_without_deduplicating_findings(memos, coerce):
    source = ambiguous() + caller(coerce)
    findings = mod._detect_cross_function_collapse({'local.py': source}, {'local.py': graph(12)})
    assert len(findings) == (12 if coerce else 0)
    if coerce:
        line = source[:source.index('return values or []')].count('\n') + 1
        assert all(f.line == line for f in findings)
        assert len({id(f) for f in findings}) == 12
    query = next(memo for limit, memo in memos if limit == 256)
    assert (query.miss_count, query.hit_count) == (1, 11)


def test_cross_file_cache_keeps_first_match_and_same_file_precedence(memos):
    sources = {'a.py': ambiguous(), 'b.py': ambiguous('[]') + caller(), 'c.py': caller()}
    findings = mod._detect_cross_function_collapse(
        sources, {'c.py': graph(3), 'b.py': graph(2)},
    )
    assert [f.file for f in findings] == ['c.py'] * 3 + ['b.py'] * 2
    assert all('(from a.py:fetch)' in f.write_value for f in findings[:3])
    assert all('(from b.py:fetch)' in f.write_value for f in findings[3:])


def test_cross_file_absence_is_an_indexed_query_fact():
    findings = mod._detect_cross_function_collapse(
        {'a.py': ambiguous(), 'b.py': caller()}, {'b.py': graph(10, callee='absent')},
    )
    assert findings == []


def test_falsey_first_match_does_not_fall_through_to_later_semantics(monkeypatch, memos):
    class FalseSemantics(mod._ReturnSemantics):
        def __bool__(self):
            return False

    first = FalseSemantics('fetch', 'a.py', returns_none_on_error=True, returns_none_on_success=True)
    second = mod._ReturnSemantics('fetch', 'b.py', returns_empty_on_error=True, returns_empty_on_success=True)
    semantics = {'a.py': {'fetch': first}, 'b.py': {'fetch': second}, 'c.py': {}}
    monkeypatch.setattr(mod, '_classify_returns_python', lambda path, source: semantics[path])
    assert mod._detect_cross_function_collapse(
        {'a.py': '', 'b.py': '', 'c.py': caller()}, {'c.py': graph(3)},
    ) == []


def test_replaced_coercion_helper_retains_per_edge_calls(monkeypatch):
    source = ambiguous() + caller()
    results = iter([17, None])
    seen = []

    def replacement(*args):
        seen.append(args)
        return next(results)

    monkeypatch.setattr(mod, '_find_coercion_of_call', replacement)
    findings = mod._detect_cross_function_collapse({'local.py': source}, {'local.py': graph(2)})
    assert [f.line for f in findings] == [17]
    assert len(seen) == 2 and all(args[0] is source for args in seen)


def test_source_adapter_retains_split_operations():
    calls = []

    class Source(str):
        def split(self, *args):
            calls.append(args)
            return super().split(*args)

    source = Source(ambiguous() + caller())
    findings = mod._detect_cross_function_collapse({'local.py': source}, {'local.py': graph(2)})
    assert len(findings) == 2
    assert calls == [('\n',), ('\n',)]


@pytest.mark.parametrize('field', ['caller', 'callee'])
def test_name_adapters_do_not_enter_native_coercion_memo(memos, field):
    class Name(str):
        pass

    name = Name('consume') if field == 'caller' else 'consume'
    callee = Name('fetch') if field == 'callee' else 'fetch'
    source = ambiguous() + caller()
    findings = mod._detect_cross_function_collapse(
        {'local.py': source}, {'local.py': graph(2, name=name, callee=callee)},
    )
    assert len(findings) == 2
    query = next(memo for limit, memo in memos if limit == 256)
    assert (query.miss_count, query.hit_count) == (0, 0)


def test_small_sources_keep_direct_coercion_queries(memos):
    source = ambiguous() + 'def consume():\n    values = fetch()\n    return values or []\n'
    assert len(mod._detect_cross_function_collapse({'local.py': source}, {'local.py': graph(2)})) == 2
    assert all(limit != 256 for limit, _ in memos)


def test_coercion_facts_are_scoped_to_each_source_and_invocation():
    sources = {'a.py': ambiguous() + caller(), 'b.py': ambiguous() + '\n' * 13 + caller()}
    graphs = {path: graph(2) for path in sources}
    findings = mod._detect_cross_function_collapse(sources, graphs)
    expected = {path: text[:text.index('return values or []')].count('\n') + 1 for path, text in sources.items()}
    assert [f.line for f in findings] == [expected['a.py']] * 2 + [expected['b.py']] * 2
    sources['a.py'] = ambiguous() + caller(False)
    assert [f.file for f in mod._detect_cross_function_collapse(sources, graphs)] == ['b.py'] * 2


def test_coercion_memo_eviction_recomputes_without_changing_results(memos):
    source = ambiguous() + caller()
    calls = [dict(caller=f'absent_{i}', chain=['fetch']) for i in range(257)]
    calls.append(dict(caller='absent_0', chain=['fetch']))
    assert mod._detect_cross_function_collapse({'local.py': source}, {'local.py': {'calls': calls}}) == []
    query = next(memo for limit, memo in memos if limit == 256)
    assert len(query) == 256 and query.miss_count == 258


def test_partial_suffix_index_retains_unindexed_matches():
    definitions = ''.join(ambiguous().replace('fetch', f'fetch_{i}') for i in range(513))
    source = caller().replace('fetch', 'fetch_512')
    findings = mod._detect_cross_function_collapse(
        {'a.py': definitions, 'b.py': source}, {'b.py': graph(2, callee='fetch_512')},
    )
    assert len(findings) == 2
    assert all('(from a.py:fetch_512)' in f.write_value for f in findings)


def test_suffix_index_bound_and_first_match():
    sem = mod._ReturnSemantics('fetch', 'a.py')
    funcs = {'first.py:fetch': sem, 'second.py:fetch': sem}
    funcs.update({f'a.py:fetch_{i}': sem for i in range(513)})
    keys, complete = mod._callee_suffix_keys(funcs)
    assert len(keys) == 512 and not complete
    assert keys['fetch'] == 'first.py:fetch'
    assert 'fetch_512' not in keys


def test_suffix_index_handles_colons_in_full_keys(monkeypatch):
    sem = mod._ReturnSemantics('prefix:fetch', 'a.py', returns_none_on_error=True, returns_none_on_success=True)
    monkeypatch.setattr(mod, '_classify_returns_python', lambda path, source: {'prefix:fetch': sem} if path == 'a.py' else {})
    monkeypatch.setattr(mod, '_find_coercion_of_call', lambda *args: 17)
    findings = mod._detect_cross_function_collapse(
        {'a.py': '', 'b.py': caller()}, {'b.py': graph(2, callee='prefix:fetch')},
    )
    assert len(findings) == 2
    assert all('(from a.py:prefix:fetch)' in f.write_value for f in findings)


@pytest.mark.parametrize('field', ['caller', 'callee'])
@pytest.mark.parametrize('length', [512, 513], ids=['at-limit', 'over-limit'])
def test_native_name_admission_limit(memos, field, length):
    name = 'c' * length if field == 'caller' else 'consume'
    callee = 'f' * length if field == 'callee' else 'fetch'
    sources = {'a.py': ambiguous().replace('fetch', callee),
               'b.py': caller().replace('consume', name).replace('fetch', callee)}
    findings = mod._detect_cross_function_collapse(sources, {'b.py': graph(2, name=name, callee=callee)})
    assert len(findings) == 2
    query = next(memo for limit, memo in memos if limit == 256)
    assert (query.miss_count, query.hit_count) == ((1, 1) if length == 512 else (0, 0))


def test_single_edge_needs_no_coercion_memo(memos):
    source = ambiguous() + caller()
    assert len(mod._detect_cross_function_collapse({'local.py': source}, {'local.py': graph(1)})) == 1
    assert memos == []


def test_foreign_call_sequence_keeps_direct_operations(memos):
    lengths = []

    class Calls(list):
        def __len__(self):
            lengths.append(None)
            return super().__len__()

    calls = Calls(graph(2)['calls'])
    findings = mod._detect_cross_function_collapse(
        {'local.py': ambiguous() + caller()}, {'local.py': {'calls': calls}},
    )
    assert len(findings) == 2 and lengths == [] and memos == []

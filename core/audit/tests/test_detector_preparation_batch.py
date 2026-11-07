"""Prepared detector queries preserve legacy scopes, ordering and overrides."""

import ast
from dataclasses import asdict


from core.audit import fail_open_detector as fail
from core.audit import sentinel_collapse as sentinel
from core.audit import value_space_checker as values


def test_return_contexts_match_both_direct_helpers_for_every_return():
    source = '''
def outer():
    if error:
        return None
    else:
        return []
    try:
        def inner():
            try:
                return None
            except Exception:
                return []
        return {}
    except Exception:
        if ready:
            return None
        return []
    if value is None:
        return {}
    return 42
'''
    tree = ast.parse(source)
    for func in (node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)):
        starts, ends, errors = sentinel._return_contexts(func)
        for node in ast.walk(func):
            if isinstance(node, ast.Return):
                covered = any(start <= node.lineno <= end for start, end in zip(starts, ends))
                assert covered == sentinel._is_inside_except(node, func)
                assert (id(node) in errors) == sentinel._is_inside_error_if(node, func)


def test_native_return_context_is_prepared_once(monkeypatch):
    calls = []
    actual = sentinel._return_contexts

    def observed(node):
        calls.append(node.name)
        return actual(node)

    monkeypatch.setattr(sentinel, '_return_contexts', observed)
    source = 'def many():\n' + '    if error:\n        return None\n' * 100 + '    return []\n'
    result = sentinel._classify_returns_python('a.py', source)
    assert calls == ['many']
    assert result['many'].returns_none_on_error
    assert result['many'].returns_empty_on_success


def test_failed_optional_return_preparation_retains_direct_results(monkeypatch):
    source = 'def f():\n    try:\n        return None\n    except Exception:\n        return None\n'
    expected = sentinel._classify_returns_python('a.py', source)

    def refused(*args):
        raise RecursionError('optional preparation refusal')

    monkeypatch.setattr(sentinel, '_return_contexts', refused)
    assert sentinel._classify_returns_python('a.py', source) == expected


def test_return_helper_overrides_keep_per_return_calls(monkeypatch):
    calls = []

    def replaced(node, func):
        calls.append(node.lineno)
        return len(calls) % 2 == 1

    monkeypatch.setattr(sentinel, '_is_inside_except', replaced)
    source = 'def f():\n    return None\n    return None\n'
    result = sentinel._classify_returns_python('a.py', source)
    assert calls == [2, 3]
    assert result['f'].returns_none_on_error and result['f'].returns_none_on_success


def test_return_source_adapter_keeps_direct_context_queries(monkeypatch):
    class Source(str):
        pass

    def unexpected(*args):
        raise AssertionError('foreign source used prepared contexts')

    monkeypatch.setattr(sentinel, '_return_contexts', unexpected)
    result = sentinel._classify_returns_python('a.py', Source('def f():\n    return None\n'))
    assert result['f'].returns_none_on_success


def test_fail_open_success_membership_preserves_all_except_findings():
    source = 'def f():\n' + '    return []\n' * 100 + '    try:\n        work()\n    except Exception:\n        return []\n'
    result = fail._detect_error_conflated_with_empty('a.py', source)
    assert len(result) == 1 and result[0].line == 105
    assert result[0].pattern_type == 'error_conflated_with_empty'


def test_replaced_literal_normalizer_retains_return_operations(monkeypatch):
    seen = []
    actual = fail._normalise_literal

    def observed(value):
        seen.append(value)
        return actual(value)

    monkeypatch.setattr(fail, '_normalise_literal', observed)
    source = 'def f():\n    return []\n    try:\n        work()\n    except Exception:\n        return []\n'
    assert len(fail._detect_error_conflated_with_empty('a.py', source)) == 1
    assert seen == ['[]', '[]']


def test_fail_open_start_queries_reuse_only_immutable_line_facts(monkeypatch):
    source = '# padding\n' * 700 + 'def consume():\n    values = fetch()\n    if not values:\n        return True\n'
    body_calls = []
    actual_body = fail._extract_caller_body

    def body(*args):
        body_calls.append(args)
        return actual_body(*args)

    memos = []
    actual_memo = fail.BoundedMemo

    def memo(limit):
        result = actual_memo(limit)
        memos.append(result)
        return result

    monkeypatch.setattr(fail, '_extract_caller_body', body)
    monkeypatch.setattr(fail, 'BoundedMemo', memo)
    silent = [fail.FailOpenPattern('a.py', 'fetch', 1, 'truncation_not_signaled', 'test', 'high')]
    graph = {'a.py': {'calls': [{'caller': 'consume', 'chain': ['fetch']}] * 10}}
    findings = fail._detect_consumer_fail_open({'a.py': source}, graph, silent)
    assert len(findings) == 10 and len({id(f) for f in findings}) == 10
    assert len(body_calls) == 10  # delegated extraction still runs for every edge
    assert len(memos) == 1 and (memos[0].miss_count, memos[0].hit_count) == (1, 9)


def test_replaced_start_line_helper_retains_each_edge_result(monkeypatch):
    source = '# padding\n' * 700 + 'def consume():\n    if not values:\n        return True\n'
    monkeypatch.setattr(fail, '_extract_caller_body', lambda *args: 'if not values:\n    return True')
    numbers = iter([17, 29])
    monkeypatch.setattr(fail, '_function_start_line', lambda *args: next(numbers))
    silent = [fail.FailOpenPattern('a.py', 'fetch', 1, 'truncation_not_signaled', 'test', 'high')]
    graph = {'a.py': {'calls': [{'caller': 'consume', 'chain': ['fetch']}] * 2}}
    assert [item.line for item in fail._detect_consumer_fail_open({'a.py': source}, graph, silent)] == [17, 29]


def test_native_value_join_keeps_first_consumer_and_empty_normalization():
    produced = {'000', 'ABC', 'Mixed', 'Missing'}
    consumed = {'', '0', '00', 'abc', 'ABC0', 'mixed', 'other', 'more', 'padding'}
    producer = values._FunctionLiterals('p.py', 'produce', produced=produced)
    consumer = values._FunctionLiterals('c.py', 'consume', consumed=consumed)
    result = values._compute_gaps([(producer, consumer, 'high')])
    expected = []
    for value in sorted(produced - consumed):
        for candidate in consumed:
            if values._normalize_for_comparison(candidate) == values._normalize_for_comparison(value):
                expected.append(f'{value!r} vs {candidate!r} (format mismatch)')
                break
    assert len(result) == 1 and result[0].format_mismatches == expected
    assert result[0].unhandled == ['Missing']


def test_replaced_normalizer_preserves_the_direct_value_join(monkeypatch):
    calls = []
    actual = values._normalize_for_comparison

    def observed(value):
        calls.append(value)
        return actual(value)

    monkeypatch.setattr(values, '_normalize_for_comparison', observed)
    producer = values._FunctionLiterals('p.py', 'p', produced={'A', 'B'})
    consumer = values._FunctionLiterals('c.py', 'c', consumed=set('abcdefghij'))
    result = values._compute_gaps([(producer, consumer, 'high')])
    assert result and len(calls) >= len(consumer.consumed)
    assert result[0].unhandled == []


def test_duplicate_value_links_retain_first_confidence():
    p = values._FunctionLiterals('p.py', 'p', produced={'A', 'B'})
    c = values._FunctionLiterals('c.py', 'c', consumed=set('abcdefghij'))
    findings = values._compute_gaps([(p, c, 'medium'), (p, c, 'high')])
    assert len(findings) == 1 and asdict(findings[0])['confidence'] == 'medium'


def test_replaced_ast_dump_keeps_per_return_predicate_operations(monkeypatch):
    calls = []
    actual = sentinel.ast

    class AstView:
        def __getattr__(self, name):
            return getattr(actual, name)

        def dump(self, node):
            calls.append(node)
            return actual.dump(node)

    monkeypatch.setattr(sentinel, 'ast', AstView())
    result = sentinel._classify_returns_python('a.py', 'def f():\n    if error:\n        return None\n    return None\n')
    assert len(calls) == 2
    assert result['f'].returns_none_on_error and result['f'].returns_none_on_success


def test_perfect_alignment_keeps_replaced_template_predicate_calls(monkeypatch):
    calls = []
    actual = values._is_template

    def observed(value):
        calls.append(value)
        return actual(value)

    monkeypatch.setattr(values, '_is_template', observed)
    p = values._FunctionLiterals('p.py', 'p', produced={'one', 'two'})
    c = values._FunctionLiterals('c.py', 'c', consumed={'one', 'two'})
    assert values._compute_gaps([(p, c, 'high')]) == []
    assert set(calls) == p.produced and len(calls) == 2


def test_native_value_join_bounds_normalization_work(monkeypatch):
    calls = []
    actual = values._normalize_for_comparison

    def observed(value):
        calls.append(value)
        return actual(value)

    # Instrument the trusted implementation at the consumer seam. Replaced
    # implementations without this marker retain direct calls in the test above.
    monkeypatch.setattr(values, '_normalize_for_comparison', observed)
    monkeypatch.setattr(values, '_NORMALIZE_IMPL', observed)
    p = values._FunctionLiterals('p.py', 'p', produced={f'KEY_{i}' for i in range(200)})
    c = values._FunctionLiterals('c.py', 'c', consumed={f'key_{i}' for i in range(200)})
    result = values._compute_gaps([(p, c, 'high')])
    assert len(result) == 1 and len(result[0].format_mismatches) == 200
    assert len(calls) <= 4 * 200


def test_aligned_first_value_pair_still_marks_duplicate_key_seen():
    first = values._FunctionLiterals('p.py', 'p', produced={'a'})
    later = values._FunctionLiterals('p.py', 'p', produced={'b'})
    consumer = values._FunctionLiterals('c.py', 'c', consumed={'a'})
    assert values._compute_gaps([(first, consumer, 'medium'), (later, consumer, 'high')]) == []


def test_replaced_start_line_provider_keeps_per_edge_operations(monkeypatch):
    source = '# padding\n' * 700 + 'def consume():\n    if not values:\n        return True\n'
    monkeypatch.setattr(fail, '_extract_caller_body', lambda *args: 'if not values:\n    return True')
    snapshots = iter([['consume()'], ['padding', 'consume()']])
    monkeypatch.setattr(fail, 'split_lines', lambda *args: next(snapshots))
    silent = [fail.FailOpenPattern('a.py', 'fetch', 1, 'truncation_not_signaled', 'test', 'high')]
    graph = {'a.py': {'calls': [{'caller': 'consume', 'chain': ['fetch']}] * 2}}
    assert [item.line for item in fail._detect_consumer_fail_open({'a.py': source}, graph, silent)] == [1, 2]

"""Context shortcuts retain default matching and adapter comparison rules."""

from copy import deepcopy
import re

import pytest

from core.audit import context


def role(source):
    return context._classify_role(None, 'source.c', 'handle', callers=[], callees=[], source=source)


@pytest.mark.parametrize('source', [
    pytest.param('// no relevant tokens\n' * 500, id='absent'),
    pytest.param('// padding\n' * 500 + 'memcpy(a,b,n);', id='plain-api'),
    pytest.param('// padding\n' * 500 + 'SUBPROCESS.Popen(args);', id='mixed-case'),
    pytest.param('// padding\n' * 500 + 'run(args);', id='optional-module-prefix'),
    pytest.param('// padding\n' * 500 + 'πmemcpy(a,b,n);', id='unicode-word-boundary'),
    pytest.param('// padding\n' * 500 + 'memcpy_extra(a,b,n);', id='identifier-suffix'),
])
def test_role_detection_keeps_exact_matcher_results_and_order(source):
    expected = [api for api, pattern in context._DANGEROUS_API_RE.items() if pattern.search(source.lower())]
    result = role(source)
    assert result['dangerous_apis'] == expected
    assert result['role'] == 'leaf'


def test_replaced_pattern_does_not_inherit_the_original_literal(monkeypatch):
    monkeypatch.setattr(context, '_DANGEROUS_API_RE', {'memcpy': re.compile('different_marker')})
    assert role('// padding\n' * 500 + 'different_marker')['dangerous_apis'] == ['memcpy']


def test_replaced_matcher_failure_is_not_skipped(monkeypatch):
    class Matcher:
        def search(self, source):
            raise RuntimeError('owned matcher failure')

    monkeypatch.setattr(context, '_DANGEROUS_API_RE', {'memcpy': Matcher()})
    with pytest.raises(RuntimeError, match='owned matcher failure'):
        role('unrelated\n' * 1000)


def test_lowered_text_adapter_does_not_get_a_new_containment_operation():
    class Lowered(str):
        def __contains__(self, value):
            raise AssertionError('adapter containment was invoked')

    class Source(str):
        def lower(self):
            return Lowered('// padding\n' * 500 + 'memcpy(a,b,n);')

    assert 'memcpy' in role(Source('ignored'))['dangerous_apis']


def test_role_lookup_does_not_reuse_results_across_sources():
    prefix = '// padding\n' * 500
    assert role(prefix)['dangerous_apis'] == []
    assert 'memcpy' in role(prefix + 'memcpy(a,b,n);')['dangerous_apis']
    assert role(prefix)['dangerous_apis'] == []


def test_entry_point_sinks_remain_borrowed_and_unchanged():
    supplied = ['repeat', 'repeat']
    data = {'entry_points': [{'file': 'source.c', 'name': 'handle', 'reachable_sinks': supplied}],
            'sinks': [{'file': 'source.c', 'function': 'handle', 'target': 'other'}]}
    assert context._extract_sinks(data, 'source.c', 'handle') is supplied
    assert supplied == ['repeat', 'repeat']


def test_native_sink_order_and_transitive_empty_values_are_preserved():
    data = {'sinks': [{'file': 'source.c', 'function': 'handle', 'target': target}
                      for target in ['one', '', 'two', 'one']],
            'sink_discovery': {'transitive_reach': [
                {'file': 'source.c', 'function': 'handle', 'reachable_sinks': ['two', '', 'three', None, None]},
            ]}}
    original = deepcopy(data)
    assert context._extract_sinks(data, 'source.c', 'handle') == ['one', 'two', '', 'three', None]
    assert data == original


def test_retained_sink_adapter_keeps_native_comparison_semantics():
    calls = []

    class Target:
        __hash__ = None

        def __eq__(self, other):
            calls.append(other)
            return type(other) is str and other == 'alias'

    target = Target()
    data = {'sinks': [{'file': 'source.c', 'function': 'handle', 'target': t}
                      for t in [target, 'alias', 'later']]}
    result = context._extract_sinks(data, 'source.c', 'handle')
    assert len(result) == 2 and result[0] is target and result[1] == 'later'
    assert calls == ['alias', 'later']


def test_unhashable_string_sink_keeps_legacy_equality():
    class Target(str):
        __hash__ = None

    target = Target('send')
    data = {'sinks': [{'file': 'source.c', 'function': 'handle', 'target': t}
                      for t in [target, 'send', 'other', target]]}
    result = context._extract_sinks(data, 'source.c', 'handle')
    assert len(result) == 2 and result[0] is target and result[1] == 'other'


def test_sink_index_returns_to_ordered_comparisons_for_an_adapter():
    prefix = [f'call_{i}' for i in range(16)]
    calls = []

    class Target:
        __hash__ = None

        def __eq__(self, other):
            calls.append(other)
            return type(other) is str and other == 'alias'

    target = Target()
    data = {'sinks': [{'file': 'source.c', 'function': 'handle', 'target': t}
                      for t in prefix + [target, 'alias', 'later']]}
    result = context._extract_sinks(data, 'source.c', 'handle')
    assert result[:16] == prefix
    assert result[16] is target and result[17:] == ['later']
    assert calls == prefix + ['alias', 'later']

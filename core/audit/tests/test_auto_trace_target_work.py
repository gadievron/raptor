"""Trace target indexing preserves suffix matching and first-site ordering."""

from copy import deepcopy

from core.audit import context


def reach(target, *, file='source.c', function='read'):
    return {'file': file, 'function': function, 'reachable_sinks': [target],
            'chain': [{'file': 'down.c', 'function': 'forward'}]}


def sink(target, *, file='source.c', function='read'):
    return {'file': file, 'function': function, 'target': target}


def test_native_targets_do_not_scan_previously_built_trace_ids(monkeypatch):
    def unexpected(*args):
        raise AssertionError('native target scanned prior trace IDs')

    monkeypatch.setattr(context, 'any', unexpected, raising=False)
    targets = [f'call_{i}' for i in range(200)]
    data = {'sink_discovery': {'transitive_reach': [reach('forwarded')]},
            'sinks': [sink(t) for t in targets + ['forwarded'] + targets]}
    original = deepcopy(data)
    result = context._build_auto_traces(data, 'source.c', 'read')
    assert [row['sink']['name'] for row in result] == ['forwarded'] + targets
    assert result[0]['id'] == 'auto-source.c:read->forwarded'
    assert all(row['role'] == 'sink' and row['auto_trace'] for row in result[1:])
    assert data == original


def test_duplicate_transitive_traces_are_retained_in_original_order():
    data = {'sink_discovery': {'transitive_reach': [reach('send'), reach('send')]},
            'sinks': [sink('send'), sink('later'), sink('later')]}
    result = context._build_auto_traces(data, 'source.c', 'read')
    assert [row['sink']['name'] for row in result] == ['send', 'send', 'later']
    assert result[0] == result[1]
    assert result[0] is not result[1]


def test_terminal_and_compound_targets_keep_legacy_arrow_suffixes():
    data = {'sink_discovery': {'transitive_reach': [reach('prefix->send')]},
            'sinks': [sink('send'), sink('prefix->send'), sink('other->store'),
                      sink('store'), sink('other->store'), sink('plain')]}
    result = context._build_auto_traces(data, 'source.c', 'read')
    assert [row['sink']['name'] for row in result] == ['prefix->send', 'other->store', 'plain']


def test_compound_queries_can_match_inside_generated_id_prefixes():
    file = 'prefix->suffix.c'
    data = {'sinks': [sink('first', file=file), sink('suffix.c:read->first', file=file),
                      sink('first', file=file)]}
    result = context._build_auto_traces(data, file, 'read')
    assert [row['sink']['name'] for row in result] == ['first']


def test_non_string_transitive_target_is_indexed_by_its_actual_id():
    data = {'sink_discovery': {'transitive_reach': [reach(13)]}, 'sinks': [sink('13')]}
    result = context._build_auto_traces(data, 'source.c', 'read')
    assert len(result) == 1
    assert result[0]['sink']['name'] == 13
    assert result[0]['id'].endswith('->13')


def test_adapted_queries_retain_formatting_calls_and_do_not_get_hashed():
    calls = []

    class Target(str):
        __hash__ = None

        def __contains__(self, value):
            raise AssertionError('adapter containment changed')

        def __format__(self, spec):
            calls.append(spec)
            return 'second'

    data = {'sink_discovery': {'transitive_reach': [reach('first'), reach('second')]},
            'sinks': [sink(Target('display'))]}
    result = context._build_auto_traces(data, 'source.c', 'read')
    assert [row['sink']['name'] for row in result] == ['first', 'second']
    assert calls == ['', '']


def test_new_adapted_target_supplies_the_indexed_id_suffix():
    calls = []

    class Target:
        def __format__(self, spec):
            calls.append(spec)
            return 'prefix->actual'

    target = Target()
    data = {'sinks': [sink(target), sink('actual'), sink('prefix->actual')]}
    result = context._build_auto_traces(data, 'source.c', 'read')
    assert len(result) == 1
    assert result[0]['sink']['name'] is target
    assert result[0]['id'] == 'auto-direct-source.c:read->prefix->actual'
    assert calls == ['']


def test_filtering_and_empty_targets_keep_existing_behavior():
    data = {'sink_discovery': {'transitive_reach': [reach('send', file='other.c')]},
            'sinks': [sink(''), sink(None), sink(0), sink('wrong', function='other'),
                      sink('wrong', file='other.c'), sink('send')]}
    result = context._build_auto_traces(data, 'source.c', 'read')
    assert [row['sink']['name'] for row in result] == ['send']

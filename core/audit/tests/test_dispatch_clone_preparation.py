"""Dispatch aggregation and clone facts retain ordering and override semantics."""
from types import SimpleNamespace

from core.audit import clone_drift as clone
from core.audit import dispatch_table as dispatch


def test_native_chunks_preserve_leading_lf_and_file_order(monkeypatch):
    seen = []
    pattern = dispatch._IOCTL_CASE_RE

    class Observed:
        def finditer(self, text):
            seen.append(text)
            return pattern.finditer(text)

    monkeypatch.setattr(dispatch, '_IOCTL_CASE_RE', Observed())
    gaps = [{'file': 'b.c' if i % 2 else 'a.c', 'name': f'f{i}', 'source': f'body{i}'} for i in range(10)]
    assert dispatch.find_dispatch_members(gaps) == {}
    assert seen == [''.join('\nbody' + str(i) for i in range(0, 10, 2)), ''.join('\nbody' + str(i) for i in range(1, 10, 2))]


def test_foreign_gap_mappings_retain_one_pass_operations():
    calls = []

    class Gap(dict):
        def get(self, key, default=None):
            calls.append(key)
            return super().get(key, default)

    gaps = [Gap(file='a.c', name=f'f{i}', source=f'.read = f{i},') for i in range(8)]
    assert len(dispatch.find_dispatch_members(gaps)['a.c']) == 8
    assert calls == ['file', 'name', 'source'] * 8


def test_source_adapters_retain_concatenation_operations():
    calls = []

    class Source(str):
        def __radd__(self, other):
            calls.append(other)
            return other + str(self)

    gaps = [{'file': 'a.c', 'name': f'f{i}', 'source': Source(f'.read = f{i},')} for i in range(8)]
    assert len(dispatch.find_dispatch_members(gaps)['a.c']) == 8
    assert len(calls) == 8
    assert calls[0] == '\n' and calls[1] == '\n.read = f0,\n'


def _legacy_handlers(members):
    result = {}
    for member in members:
        key = member.table_field or member.name
        candidate, suffix = key, 2
        while candidate in result:
            candidate = f'{key}#{suffix}'
            suffix += 1
        result[candidate] = member.name
    return result


def test_suffixes_keep_first_available_key_including_literal_suffix_collisions(monkeypatch):
    fields = ['read', 'read#2', 'read', 'read#3', 'read', 'read#2', 'read'] * 20
    members = [dispatch.DispatchMember(f'f{i}', 'a.c', field) for i, field in enumerate(fields)]
    monkeypatch.setattr(dispatch, 'find_dispatch_members', lambda gaps: {'a.c': members})
    assert dispatch.build_dispatch_tables([])[0].handlers == _legacy_handlers(members)


def test_foreign_field_keys_keep_hash_and_equality_operations(monkeypatch):
    operations = []

    class Field(str):
        def __hash__(self):
            operations.append(('hash', str(self)))
            return super().__hash__()

        def __eq__(self, other):
            operations.append(('equal', str(self), str(other)))
            return super().__eq__(other)

    members = [dispatch.DispatchMember(str(i), 'a.c', Field('read') if i == 2 else 'read') for i in range(8)]
    operations.clear()
    expected = _legacy_handlers(members)
    expected_ops = operations.copy()
    operations.clear()
    monkeypatch.setattr(dispatch, 'find_dispatch_members', lambda gaps: {'a.c': members})
    assert dispatch.build_dispatch_tables([])[0].handlers == expected
    assert operations == expected_ops


def test_capability_membership_keeps_first_occurrence_order():
    source = ' '.join(f'capable(CAP_{i % 200})' for i in range(600))
    source += ' ns_capable(ns, CAP_EXTRA) capable(CAP_0)'
    caps = dispatch.find_capability_checks([{'file': 'a.c', 'name': 'f', 'source': source}])
    assert caps['a.c']['f'] == [f'CAP_{i}' for i in range(200)] + ['CAP_EXTRA']


def test_foreign_capability_capture_retains_list_equality_operations(monkeypatch):
    operations = []

    class Capability(str):
        def __eq__(self, other):
            operations.append((str(self), str(other)))
            return super().__eq__(other)

    values = ['CAP_A', Capability('CAP_A'), 'CAP_B', Capability('CAP_B')]
    expected = []
    for value in values:
        if value not in expected:
            expected.append(value)
    expected_ops = operations.copy()
    operations.clear()

    class Pattern:
        def finditer(self, source):
            return iter(SimpleNamespace(group=lambda index, value=value: value) for value in values)

    monkeypatch.setattr(dispatch, '_CAPABILITY_PATTERNS', [Pattern()])
    result = dispatch.find_capability_checks([{'file': 'a.c', 'name': 'f', 'source': 'source'}])
    assert result['a.c']['f'] == expected and operations == expected_ops


def test_missing_member_lists_are_fresh_and_keep_member_order(monkeypatch):
    members = [dispatch.DispatchMember('b', 'a.c'), dispatch.DispatchMember('a', 'a.c')]
    monkeypatch.setattr(dispatch, 'find_dispatch_members', lambda gaps: {'a.c': members})
    monkeypatch.setattr(dispatch, 'find_capability_checks', lambda gaps: {'a.c': {'init': ['CAP_A', 'CAP_B']}})
    rows = dispatch.check_capability_displacement([])
    assert [r.capability for r in rows] == ['CAP_A', 'CAP_B']
    assert rows[0].dispatch_members_without == rows[1].dispatch_members_without == ['b', 'a']
    rows[0].dispatch_members_without.pop()
    assert rows[1].dispatch_members_without == ['b', 'a']


def test_foreign_members_keep_accesses_even_for_suppressed_capability(monkeypatch):
    operations = []

    class Member:
        def __init__(self, name):
            self.value = name

        @property
        def name(self):
            operations.append(self.value)
            return self.value

    members = [Member('a'), Member('b')]
    monkeypatch.setattr(dispatch, 'find_dispatch_members', lambda gaps: {'a.c': members})
    monkeypatch.setattr(dispatch, 'find_capability_checks', lambda gaps: {'a.c': {'init': ['CAP_A', 'CAP_B'], 'a': ['CAP_A']}})
    rows = dispatch.check_capability_displacement([])
    assert [r.capability for r in rows] == ['CAP_B']
    assert operations == ['a', 'b', 'a', 'b', 'b', 'a', 'a', 'b', 'b']


def test_streamed_guard_features_match_both_direct_queries():
    lines = ['int f() {', 'if (check(x) && x <', 'if (other(y) && y <= z)', '    work();', 'while (verify(x)) {', '}']
    for separator in ['\n', '\r\n', '\r', '\x85', '\u2028', '\v']:
        text = separator.join(lines) + separator
        assert clone._guard_features(text) == (clone._guard_calls(text), clone._bound_style(text))


def test_native_large_bodies_share_guard_scan(monkeypatch):
    seen = []
    actual = clone._guard_features

    def observed(text):
        seen.append(text)
        return actual(text)

    monkeypatch.setattr(clone, '_guard_features', observed)
    a = clone._FnBody('a.c', 'a', 1, 'work();\n' * 400 + 'if (check(x)) return;', 0, frozenset())
    b = clone._FnBody('b.c', 'b', 2, 'work();\n' * 400, 0, frozenset())
    assert clone._divergences(a, b)[0] == ('guard', 'check', b)
    assert seen == [a.text, b.text]


def test_foreign_clone_text_keeps_display_split_operations():
    operations = []

    class Source(str):
        def splitlines(self):
            operations.append(str(self))
            return super().splitlines()

    a = clone._FnBody('a.c', 'a', 1, Source('if (check(x)) return;'), 0, frozenset())
    b = clone._FnBody('b.c', 'b', 2, Source('work();'), 0, frozenset())
    assert clone._divergences(a, b)
    assert operations == [a.text, b.text, a.text, b.text]


def _anchors(monkeypatch, *, body_size=20):
    body = '\n'.join('    work(value);' for _ in range(body_size))
    monkeypatch.setattr(clone, '_grammar_ready', lambda: True)
    monkeypatch.setattr(clone, 'function_spans', lambda sources: [('a.c', 'f', 7, body.split('\n'))])
    anchors = [{'file': 'a.c', 'name': 'f', 'guard': 'verify', 'sha': 'abc123', 'fixed_region': 'if (verify(value)) return;\n' + body}] * 5
    return anchors, body


def test_body_fingerprints_are_reused_only_within_one_anchor_run(monkeypatch):
    anchors, body = _anchors(monkeypatch)
    memos = []
    actual = clone.BoundedMemo

    def observed(limit):
        memo = actual(limit)
        memos.append(memo)
        return memo

    monkeypatch.setattr(clone, 'BoundedMemo', observed)
    first = clone.fix_anchored_drift(anchors, {'a.c': body})
    second = clone.fix_anchored_drift(anchors, {'a.c': body})
    assert len(first) == len(second) == 5
    assert [r.to_dict() for r in first] == [r.to_dict() for r in second]
    assert first[0] is not second[0]
    assert [(m.miss_count, m.hit_count) for m in memos] == [(1, 4), (1, 4)]


def test_replaced_normalizer_keeps_each_anchor_operation(monkeypatch):
    anchors, body = _anchors(monkeypatch)
    seen = []
    actual = clone._normalise_tokens

    def observed(text):
        seen.append(text)
        return actual(text)

    monkeypatch.setattr(clone, '_normalise_tokens', observed)
    assert len(clone.fix_anchored_drift(anchors, {'a.c': body})) == 5
    assert seen == [body, body] * 5


def test_oversized_body_bypasses_fingerprint_memo(monkeypatch):
    anchors, body = _anchors(monkeypatch, body_size=1200)
    assert len(body) > 16 * 1024
    memos = []
    actual = clone.BoundedMemo

    def observed(limit):
        memo = actual(limit)
        memos.append(memo)
        return memo

    monkeypatch.setattr(clone, 'BoundedMemo', observed)
    clone.fix_anchored_drift(anchors, {'a.c': body})
    assert len(memos) == 1 and (memos[0].miss_count, memos[0].hit_count) == (0, 0)


def test_replaced_divergence_helpers_keep_original_order(monkeypatch):
    calls = []
    for name in ['_guard_calls', '_security_calls', '_bound_style']:
        actual = getattr(clone, name)

        def observed(text, name=name, actual=actual):
            calls.append((name, text[-1]))
            return actual(text)

        monkeypatch.setattr(clone, name, observed)
    a = clone._FnBody('a.c', 'a', 1, 'work();\n' * 400 + 'a', 0, frozenset())
    b = clone._FnBody('b.c', 'b', 1, 'work();\n' * 400 + 'b', 0, frozenset())
    clone._divergences(a, b)
    assert calls == [(name, text) for name in ['_guard_calls', '_security_calls', '_bound_style'] for text in ['a', 'b']]


def test_replaced_sorter_keeps_bound_queries_after_sort_callbacks(monkeypatch):
    import re

    actual = sorted

    def observed(values):
        monkeypatch.setattr(clone, '_STRICT_BOUND_RE', re.compile('never_matches'))
        return actual(values)

    monkeypatch.setattr(clone, 'sorted', observed, raising=False)
    a = clone._FnBody('a.c', 'a', 1, 'work();\n' * 400 + 'if (x < cap) work();', 0, frozenset())
    b = clone._FnBody('b.c', 'b', 1, 'work();\n' * 400 + 'if (x <= cap) work();', 0, frozenset())
    assert clone._divergences(a, b) == []


def test_result_constructor_override_can_update_members_between_rows(monkeypatch):
    members = [dispatch.DispatchMember('a', 'a.c'), dispatch.DispatchMember('b', 'a.c')]
    monkeypatch.setattr(dispatch, 'find_dispatch_members', lambda gaps: {'a.c': members})
    monkeypatch.setattr(dispatch, 'find_capability_checks', lambda gaps: {'a.c': {'init': ['CAP_A', 'CAP_B']}})
    actual = dispatch.CapabilityDisplacement

    def observed(**kwargs):
        row = actual(**kwargs)
        members[0].name = 'changed'
        return row

    monkeypatch.setattr(dispatch, 'CapabilityDisplacement', observed)
    rows = dispatch.check_capability_displacement([])
    assert rows[0].dispatch_members_without == ['a', 'b']
    assert rows[1].dispatch_members_without == ['changed', 'b']

"""Prepared transform checks retain sibling counts, ordering and adapter calls."""
import re
from types import SimpleNamespace

from core.audit import transform_sequence as transforms


def _rule(name='r'):
    return transforms._OrderingRule(name, [re.compile('^p')], [re.compile('^f')], 'reason', '{precede}:{follow}')


def _seq(file, function, names):
    return transforms.TransformSequence(file, function, 'v', [transforms.TransformStep(n, i + 1) for i, n in enumerate(names)])


def _violation(file, function, rule='r'):
    return transforms.TransformOrderViolation(file, function, 1, [], 'violation', 'fix', 'high', rule)


def test_sibling_index_excludes_entire_function_and_keeps_duplicate_locations(monkeypatch):
    monkeypatch.setattr(transforms, 'ORDERING_RULES', [_rule()])
    sequences = [_seq('a.c', 'a', ['p', 'f']) for _ in range(80)]
    sequences += [_seq('b.c', 'b', ['p', 'f']), _seq('c.c', 'c', ['p', 'f']), _seq('d.c', 'd', ['f', 'p'])]
    rows = [_violation('a.c', 'a'), _violation('b.c', 'b'), _violation('x.c', 'x')]
    transforms._annotate_sibling_counts(rows, sequences)
    assert [r.siblings_correct for r in rows] == [2, 81, 82]
    assert rows[0].sibling_locations == ['b.c:b', 'c.c:c']
    assert rows[1].sibling_locations == rows[2].sibling_locations == ['a.c:a'] * 5
    rows[1].sibling_locations.pop()
    assert len(rows[2].sibling_locations) == 5


def test_first_catalog_name_wins_and_unknown_annotations_survive(monkeypatch):
    first = _rule()
    second = _rule()
    second.must_precede_patterns = [re.compile('never_matches')]
    monkeypatch.setattr(transforms, 'ORDERING_RULES', [first, second, _rule('')])
    rows = [_violation('a', 'a'), _violation('b', 'b', 'unknown'), _violation('c', 'c', '')]
    for row in rows[1:]:
        row.siblings_correct = 17
        row.sibling_locations = ['retained']
    transforms._annotate_sibling_counts(rows, [_seq('peer', 'f', ['p', 'f'])] * 8)
    assert rows[0].siblings_correct == 8
    assert all(r.siblings_correct == 17 and r.sibling_locations == ['retained'] for r in rows[1:])


def test_location_strings_do_not_define_exclusion_identity(monkeypatch):
    monkeypatch.setattr(transforms, 'ORDERING_RULES', [_rule()])
    sequences = [_seq('a:b', 'c', ['p', 'f']), _seq('a', 'b:c', ['p', 'f']), _seq('a', 'b:c', ['p', 'f'])] + [_seq('empty', 'empty', [])] * 5
    rows = [_violation('a:b', 'c'), _violation('a', 'b:c')]
    transforms._annotate_sibling_counts(rows, sequences)
    assert [r.siblings_correct for r in rows] == [2, 1]
    assert rows[0].sibling_locations == ['a:b:c', 'a:b:c']


def test_overlapping_and_interleaved_rule_positions_are_not_correct_siblings(monkeypatch):
    rule = _rule()
    rule.must_follow_patterns = [re.compile('^[pf]')]
    monkeypatch.setattr(transforms, 'ORDERING_RULES', [rule])
    rows = [_violation('a', 'a'), _violation('b', 'b')]
    transforms._annotate_sibling_counts(rows, [_seq('peer', 'f', ['p']), _seq('peer', 'g', ['p', 'f', 'p'])] + [_seq('empty', 'empty', [])] * 6)
    assert all(r.siblings_correct == 0 and r.sibling_locations == [] for r in rows)


def test_native_sibling_index_is_built_once_per_selected_rule(monkeypatch):
    monkeypatch.setattr(transforms, 'ORDERING_RULES', [_rule()])
    actual = transforms._correct_sibling_index
    calls = []

    def observed(rule, sequences, needed):
        calls.append(rule.name)
        return actual(rule, sequences, needed)

    monkeypatch.setattr(transforms, '_correct_sibling_index', observed)
    rows = [_violation('a', 'a') for _ in range(100)]
    transforms._annotate_sibling_counts(rows, [_seq('peer', 'f', ['p', 'f'])] * 50)
    assert calls == ['r'] and all(row.siblings_correct == 50 for row in rows)


def test_instance_rule_override_keeps_all_legacy_match_operations(monkeypatch):
    rule = _rule()
    calls = []
    precede, follow = rule.matches_precede, rule.matches_follow

    def observed_precede(name):
        calls.append(('p', name))
        return precede(name)

    def observed_follow(name):
        calls.append(('f', name))
        return follow(name)

    monkeypatch.setattr(rule, 'matches_precede', observed_precede)
    monkeypatch.setattr(rule, 'matches_follow', observed_follow)
    monkeypatch.setattr(transforms, 'ORDERING_RULES', [rule])
    rows = [_violation('a', 'a'), _violation('b', 'b')]
    transforms._annotate_sibling_counts(rows, [_seq('peer', 'f', ['p', 'f'])] + [_seq('empty', 'empty', [])] * 7)
    assert len(calls) == 14 and all(row.siblings_correct == 1 for row in rows)


def test_foreign_steps_keep_per_violation_reads(monkeypatch):
    monkeypatch.setattr(transforms, 'ORDERING_RULES', [_rule()])
    calls = []

    class Step:
        def __init__(self, name):
            self.name = name

        @property
        def call_name(self):
            calls.append(self.name)
            return self.name

    sequence = _seq('peer', 'f', [])
    sequence.steps = [Step('p'), Step('f')]
    rows = [_violation('a', 'a'), _violation('b', 'b')]
    transforms._annotate_sibling_counts(rows, [sequence] + [_seq('empty', 'empty', [])] * 7)
    assert calls == ['p', 'f'] * 2


def test_annotation_setter_override_can_change_later_sequence_results(monkeypatch):
    monkeypatch.setattr(transforms, 'ORDERING_RULES', [_rule()])
    sequence = _seq('peer', 'f', ['p', 'f'])
    rows = [_violation('a', 'a'), _violation('b', 'b')]
    actual = transforms.TransformOrderViolation.__setattr__

    def observed(self, name, value):
        actual(self, name, value)
        if self is rows[0] and name == 'sibling_locations':
            sequence.steps.reverse()

    monkeypatch.setattr(transforms.TransformOrderViolation, '__setattr__', observed)
    transforms._annotate_sibling_counts(rows, [sequence] + [_seq('empty', 'empty', [])] * 7)
    assert [r.siblings_correct for r in rows] == [1, 0]


def test_over_budget_annotation_uses_direct_path(monkeypatch):
    monkeypatch.setattr(transforms, 'ORDERING_RULES', [_rule()])
    rows = [_violation('a', 'a')] * 4097
    assert not transforms._native_sibling_inputs(rows, [])
    transforms._annotate_sibling_counts(rows, [_seq('peer', 'f', ['p', 'f'])] * 8)
    assert rows[0].siblings_correct == 8


def test_catalog_suffix_selection_keeps_pair_order_and_fresh_rows(monkeypatch):
    monkeypatch.setattr(transforms, 'ORDERING_RULES', [_rule()])
    seq = _seq('a.c', 'f', ['f0', 'f1', 'f2'] + [f'p{i}' for i in range(10)])
    rows = transforms._check_sequence_against_catalog(seq)
    assert len(rows) == 30 and len({id(r) for r in rows}) == 30
    assert [r.line for r in rows] == [1] * 10 + [2] * 10 + [3] * 10
    assert [r.fix for r in rows] == [f'p{i}:f{j}' for j in range(3) for i in range(10)]
    assert all(r.sequence is rows[0].sequence for r in rows)
    assert transforms._check_sequence_against_catalog(_seq('a.c', 'f', ['p'] * 100 + ['f'] * 100)) == []


def test_foreign_matcher_retains_every_name_query():
    seen = []

    class Pattern:
        def search(self, name):
            seen.append(name)
            return SimpleNamespace() if len(seen) % 2 else None

    names = ['same'] * 20
    assert transforms._matching_positions(names, Pattern()) == list(range(0, 20, 2))
    assert seen == names


def test_native_name_matching_preserves_empty_false_and_oversize_cases():
    names = ['', 'url_decode', 'plain', 'url_decode', 'plain', 'x' * 700, ''] * 100
    pattern = re.compile('decode|^$')
    for values in [names, ['url_decode', 'plain'] * 1000]:
        assert transforms._matching_positions(values, pattern) == [i for i, name in enumerate(values) if pattern.search(name)]


def test_replaced_all_retains_only_legacy_annotation_callbacks(monkeypatch):
    calls = []
    actual = all

    def observed(values):
        calls.append('all')
        return actual(values)

    monkeypatch.setattr(transforms, 'all', observed, raising=False)
    monkeypatch.setattr(transforms, 'ORDERING_RULES', [_rule()])
    names = ['url_decode', 'plain'] * 100
    assert transforms._matching_positions(names, re.compile('decode')) == list(range(0, len(names), 2))
    assert calls == []
    rows = [_violation('a', 'a'), _violation('b', 'b')]
    transforms._annotate_sibling_counts(rows, [_seq('peer', 'f', ['p', 'f'])] * 8)
    assert calls == ['all'] * 16

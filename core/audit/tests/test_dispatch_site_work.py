"""Producer joins retain site order and caps with bounded selection work."""

import logging

import pytest

from core.audit import dispatch_completeness as mod


@pytest.mark.parametrize('file', ['0.py', 'a.py', 'b.py', 'c.py', 'd.py', 'z.py'])
def test_site_prefixes_match_full_selection_in_file_order(file):
    sites = [(name, line) for name in ['a.py', 'b.py', 'd.py'] for line in [9, 1, 7, 4, 2]]
    expected_same = [site for site in sites if site[0] == file][:3]
    expected_other = [site for site in sites if site[0] != file][:2]
    assert mod._site_prefixes(sites, file) == (expected_same, expected_other)
    assert sites == [(name, line) for name in ['a.py', 'b.py', 'd.py'] for line in [9, 1, 7, 4, 2]]


def test_site_prefixes_do_not_scan_repetitive_producers():
    reads = []

    class Sites(list):
        def __iter__(self):
            raise AssertionError('producer selection scanned every site')

        def __getitem__(self, key):
            reads.append(key)
            return super().__getitem__(key)

    sites = Sites([('a.py', i) for i in range(50000)] + [('b.py', i) for i in range(50000)])
    assert mod._site_prefixes(sites, 'b.py') == (
        [('b.py', 0), ('b.py', 1), ('b.py', 2)], [('a.py', 0), ('a.py', 1)],
    )
    assert len(reads) < 80


def test_same_and_other_site_caps_keep_original_order():
    sources = {name: 'tag = "status_new"\n' * 20 for name in ['d.py', 'b.py', 'a.py', 'c.py']}
    sources['b.py'] += 'HANDLERS = {"status_old": old, "status_other": other}\n'
    gaps = mod.find_dispatch_gaps({}, sources)
    assert [(gap.produced_by, gap.confidence) for gap in gaps if gap.missing_key == 'status_new'] == [
        ('b.py:1', 'high'), ('b.py:2', 'high'), ('b.py:3', 'high'),
        ('a.py:1', 'medium'), ('a.py:2', 'medium'),
    ]


def test_noise_cap_retains_exact_discard_count(caplog):
    keys = [f'status_new_{i}' for i in range(11)]
    sources = {
        'a.py': ''.join(f'tag = "{key}"\n' * 100 for key in keys),
        'b.py': ''.join(f'tag = "{key}"\n' * 100 for key in keys)
                + 'HANDLERS = {"status_old": old, "status_other": other}\n',
    }
    with caplog.at_level(logging.DEBUG, logger=mod.__name__):
        assert mod.find_dispatch_gaps({}, sources) == []
    assert 'dropping 55 gaps' in caplog.text


def test_foreign_path_order_retains_equality_scans(monkeypatch):
    class ReversePath(str):
        def __lt__(self, other):
            return str(self) > str(other)

    def unexpected(*args):
        raise AssertionError('foreign path ordering used native binary search')

    monkeypatch.setattr(mod, '_site_prefixes', unexpected)
    sources = {
        'b.py': 'HANDLERS = {"status_old": old, "status_other": other}\n'
                + 'tag = "status_new"\n' * 20,
        ReversePath('a.py'): 'tag = "status_new"\n' * 20,
    }
    gaps = mod.find_dispatch_gaps({}, sources)
    assert [(gap.produced_by, gap.confidence) for gap in gaps if gap.missing_key == 'status_new'] == [
        ('b.py:2', 'high'), ('b.py:3', 'high'), ('b.py:4', 'high'),
        ('a.py:1', 'medium'), ('a.py:2', 'medium'),
    ]


@pytest.mark.parametrize(('candidate', 'keys', 'minimum', 'expected'), [
    ('abcX', {'abcY'}, 3, True), ('abX', {'abY'}, 3, False),
    ('Xabc', {'Yabc'}, 3, True), ('a', {'a'}, 2, False),
    ('\u03b1\u03b2\u03b3X', {'\u03b1\u03b2\u03b3Y'}, 3, True),
    ('', {''}, 0, True), ('abc', set(), 0, False),
    ('a', {'b'}, -1, True), ('abC', {'abD'}, 1.5, True),
    ('abc', {'abc'}, 1000, False), ('abc', {'abc'}, float('nan'), False),
], ids=['prefix', 'short-prefix', 'suffix', 'short-candidate', 'unicode',
        'zero', 'empty-keys', 'negative', 'fractional', 'oversized', 'nan'])
def test_affix_boundaries_preserve_existing_verdicts(candidate, keys, minimum, expected):
    assert mod._shares_affix(candidate, keys, minimum) is expected


@pytest.mark.parametrize('adapt_candidate', [False, True], ids=['key-adapter', 'candidate-adapter'])
def test_affix_adapters_keep_iteration_operations(adapt_candidate):
    calls = []

    class Text(str):
        def __iter__(self):
            calls.append('forward')
            return iter(str(self))

        def __reversed__(self):
            calls.append('backward')
            return reversed(str(self))

    candidate, key = ('Xabc', 'Yabc')
    if adapt_candidate:
        candidate = Text(candidate)
    else:
        key = Text(key)
    assert mod._shares_affix(candidate, {key})
    assert calls == ['forward', 'backward']


def test_small_native_site_groups_retain_direct_scans(monkeypatch):
    def unexpected(*args):
        raise AssertionError('tiny producer group used binary search')

    monkeypatch.setattr(mod, '_site_prefixes', unexpected)
    sources = {
        'a.py': 'tag = "status_new"\n' * 4,
        'b.py': 'HANDLERS = {"status_old": old, "status_other": other}\n'
                + 'tag = "status_new"\n' * 4,
    }
    gaps = mod.find_dispatch_gaps({}, sources)
    assert [(gap.produced_by, gap.confidence) for gap in gaps if gap.missing_key == 'status_new'] == [
        ('b.py:2', 'high'), ('b.py:3', 'high'), ('b.py:4', 'high'),
        ('a.py:1', 'medium'), ('a.py:2', 'medium'),
    ]

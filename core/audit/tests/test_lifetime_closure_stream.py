"""Lifetime tables reuse closure text while retaining their smaller reader cap."""

from collections import Counter
from functools import partial

import pytest

from core import source
from core.audit import defassign
from core.audit import lifetime_witness as lifetime
from core.audit.tests.test_macro_closure_stream import tree as tree


@pytest.fixture(autouse=True)
def owned_tables(monkeypatch):
    monkeypatch.setattr(defassign, '_TABLE_CACHE', {})
    monkeypatch.setattr(lifetime, '_LT_TABLE_CACHE', {})


def test_warm_base_reads_each_member_once_and_keeps_lifetime_macros(tree, monkeypatch):
    base = defassign._macro_table_for(tree, 'main.c')
    original = defassign.read_text_capped
    reads = Counter()
    legacy_reads = []
    def counted(path, *args, **kwargs):
        reads[path.name] += 1
        return original(path, *args, **kwargs)
    def legacy(*args, **kwargs):
        legacy_reads.append(args[0])
        return original(*args, **kwargs)
    monkeypatch.setattr(defassign, 'read_text_capped', counted)
    monkeypatch.setattr(source, 'read_text_capped', legacy)
    table = lifetime._lifetime_macro_table(tree, 'main.c')
    assert reads == {'main.c': 1, 'a.h': 1, 'b.h': 1, 'shared.h': 1}
    assert legacy_reads == []
    assert table.files_scanned == 4
    assert [definition.body for definition in table.defs['N']] == ['1', '3']
    assert table.defs['BAD'][0].variadic
    assert 'BAD' not in table.poisoned
    assert table.function_names == base.function_names
    assert table.unresolved_includes == ('"missing.h"',)
    assert lifetime._lifetime_macro_table(tree, 'main.c') is table
    assert sum(reads.values()) == 4


def test_cold_tables_read_members_twice_instead_of_three_times(tree, monkeypatch):
    original = defassign.read_text_capped
    reads = Counter()
    def counted(path, *args, **kwargs):
        reads[path.name] += 1
        return original(path, *args, **kwargs)
    monkeypatch.setattr(defassign, 'read_text_capped', counted)
    monkeypatch.setattr(source, 'read_text_capped', counted)
    assert lifetime._lifetime_macro_table(tree, 'main.c').files_scanned == 4
    assert reads == {'main.c': 2, 'a.h': 2, 'b.h': 2, 'shared.h': 2}


@pytest.mark.parametrize('layout', ['exact', 'partial-line', 'no-newline', 'at-newline'])
def test_smaller_consumer_cap_keeps_legacy_prefix(tmp_path, monkeypatch, layout):
    cap = 128
    early = '#define EARLY 1\n'
    texts = {
        'exact': early + ' ' * (cap-len(early)),
        'partial-line': early + 'x' * cap + '\n#define LATE 2\n',
        'no-newline': '#define BIG ' + '1' * (cap+20),
        'at-newline': early + ' ' * (cap-len(early)-1) + '\n#define LATE 2\n',
    }
    (tmp_path / 'main.c').write_text(texts[layout])
    original = source.read_text_capped
    legacy_reads = []
    def legacy(path):
        legacy_reads.append(path)
        return original(path, cap)
    monkeypatch.setattr(source, 'DEFAULT_MAX_SOURCE_CHARS', cap)
    monkeypatch.setattr(source, 'read_text_capped', legacy)
    table = lifetime._lifetime_macro_table(tmp_path, 'main.c')
    assert len(legacy_reads) == (0 if layout == 'exact' else 1)
    assert table.files_scanned == 1
    if layout == 'no-newline':
        assert table.defs['BIG'][0].body == '1' * (cap-len('#define BIG '))
    else:
        assert set(table.defs) == {'EARLY'}
        assert table.defs['EARLY'][0].body == '1'


def test_oversize_fallback_read_failure_keeps_file_unscanned(tmp_path, monkeypatch):
    (tmp_path / 'main.c').write_text('#define EARLY 1\n' + ' ' * 100)
    monkeypatch.setattr(source, 'DEFAULT_MAX_SOURCE_CHARS', 32)
    monkeypatch.setattr(source, 'read_text_capped', lambda path: None)
    table = lifetime._lifetime_macro_table(tmp_path, 'main.c')
    assert table.files_scanned == 0
    assert table.defs == {}


def test_late_closure_refusal_never_caches_partial_lifetime_table(tree, monkeypatch):
    defassign._macro_table_for(tree, 'main.c')
    original = defassign._iter_include_closure
    monkeypatch.setattr(defassign, '_iter_include_closure', partial(original, max_files=2))
    with pytest.raises(defassign.ProofRefusal, match='file cap'):
        lifetime._lifetime_macro_table(tree, 'main.c')
    assert lifetime._LT_TABLE_CACHE == {}

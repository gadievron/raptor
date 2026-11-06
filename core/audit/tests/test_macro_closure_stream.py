"""Macro tables consume validated include text once, in closure traversal order."""

from collections import Counter
from functools import partial

import pytest

from core.audit import defassign


@pytest.fixture
def tree(tmp_path):
    files = {
        'main.c': '#include "a.h"\n#include "b.h"\n#include "missing.h"\n#define N 1\n',
        'a.h': '#include "shared.h"\n#define A(x) ((x) + 1)\n#define BAD(x...) x\n',
        'b.h': '#include "shared.h"\n#define B 2\n',
        'shared.h': '#include "a.h"\n#define N 3\n',
    }
    for name, text in files.items():
        (tmp_path / name).write_text(text)
    return tmp_path


def test_macro_table_reads_each_closure_member_once(tree, monkeypatch):
    original = defassign.read_text_capped
    reads = Counter()
    def counted(path, *args, **kwargs):
        reads[path.name] += 1
        return original(path, *args, **kwargs)
    monkeypatch.setattr(defassign, 'read_text_capped', counted)
    table = defassign._build_macro_table(tree, 'main.c')
    assert reads == {'main.c': 1, 'a.h': 1, 'b.h': 1, 'shared.h': 1}
    assert table.files_scanned == 4
    assert [definition.body for definition in table.defs['N']] == ['1', '3']
    assert table.defs['A'][0].params == ('x',)
    assert table.defs['B'][0].body == '2'
    assert table.poisoned == {'BAD'}
    assert table.unresolved_includes == ('"missing.h"',)


def test_public_closure_keeps_breadth_first_order(tree):
    paths, unresolved = defassign.resolve_include_closure(tree, 'main.c')
    assert [path.name for path in paths] == ['main.c', 'a.h', 'b.h', 'shared.h']
    assert unresolved == ['"missing.h"']


def test_unreadable_member_keeps_unresolved_receipt(tree, monkeypatch):
    original = defassign.read_text_capped
    def unreadable(path, *args, **kwargs):
        return None if path.name == 'b.h' else original(path, *args, **kwargs)
    monkeypatch.setattr(defassign, 'read_text_capped', unreadable)
    table = defassign._build_macro_table(tree, 'main.c')
    assert table.files_scanned == 3
    assert 'B' not in table.defs
    assert table.unresolved_includes == ('"missing.h"', str(tree / 'b.h'))


@pytest.mark.parametrize('cap', ['files', 'bytes'])
def test_late_closure_refusal_does_not_cache_partial_table(tree, monkeypatch, cap):
    original = defassign._iter_include_closure
    kwargs = {'max_files': 2} if cap == 'files' else {'max_bytes': (tree / 'main.c').stat().st_size}
    monkeypatch.setattr(defassign, '_iter_include_closure', partial(original, **kwargs))
    cache = {}
    monkeypatch.setattr(defassign, '_TABLE_CACHE', cache)
    with pytest.raises(defassign.ProofRefusal, match=f'{"file" if cap == "files" else "byte"} cap'):
        defassign._macro_table_for(tree, 'main.c')
    assert cache == {}


def test_iterator_reads_lazily_and_closes_cleanly(tree, monkeypatch):
    original = defassign.read_text_capped
    reads = []
    def counted(path, *args, **kwargs):
        reads.append(path.name)
        return original(path, *args, **kwargs)
    monkeypatch.setattr(defassign, 'read_text_capped', counted)
    iterator = defassign._iter_include_closure(tree, 'main.c', unresolved=[])
    try:
        path, text = next(iterator)
        assert path.name == 'main.c'
        assert '#define N 1' in text
        assert reads == ['main.c']
    finally:
        iterator.close()

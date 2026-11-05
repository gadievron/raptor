"""Sparse enum lookup retains the existing parser's boundaries."""

import pytest

from core.inventory import macro_resolve as mr


@pytest.fixture(params=['normal', 'sparse'], autouse=True)
def enum_matching_mode(request, monkeypatch):
    if request.param == 'sparse':
        monkeypatch.setattr(mr, '_ENUM_SPARSE_MIN_SOURCE', 0)
        monkeypatch.setattr(mr, '_ENUM_SPARSE_MIN_CHARS_PER_KEYWORD', 1)


@pytest.mark.parametrize(('source', 'expected'), [
    ('prefix\nenum E { A = 1 };', [(7, ' A = 1 ')]),
    ('enum{} enum { A = 1 };', [(7, ' A = 1 ')]),
    ('enum{enum{} }', [(0, 'enum{')]),
    ('enumenum { A = 1 };', [(0, ' A = 1 ')]),
    ('myenum { A = 1 };', []),
    ('éenum { A = 1 };', []),
    ('enum' + 'x' * 256 + ' { A = 1 };', [(0, ' A = 1 ')]),
    ('enum' + 'x' * 257 + ' { A = 1 };', []),
    ('enum {', []),
])
def test_body_contents_offsets_and_head_boundaries(source, expected):
    assert list(mr._iter_enum_bodies(source)) == expected


def test_large_source_keeps_original_block_offset():
    prefix = 'ordinary();\n' * 3000
    source = prefix + 'enum E { A = 1 };\n'
    assert list(mr._iter_enum_bodies(source)) == [(len(prefix), ' A = 1 ')]


def test_subclass_retains_original_search_path():
    class Source(str):
        def __len__(self):
            raise AssertionError('legacy parser does not query text length')

        def count(self, *args):
            raise AssertionError('subclasses retain legacy searching')

    assert list(mr._iter_enum_bodies(Source('enum E { A = 1 };'))) == [(0, ' A = 1 ')]

"""Header prefixes must not create IDs from partial metadata tokens."""

import pytest

import core.audit.codeql_query_resolver as resolver


def test_cut_id_at_production_header_limit_is_not_indexed(tmp_path, monkeypatch):
    cap = resolver._HEADER_READ_BYTES
    opening = "/**\n"
    tag = " * @id cpp/owned"
    query = tmp_path / "Owned.ql"
    query.write_text(opening + " " * (cap - len(opening) - len(tag))
                     + tag + "-extra\n */\nimport cpp\nselect 1\n")
    monkeypatch.setattr(resolver, "_pack_roots", lambda _: [tmp_path])
    assert resolver._index_pack("owned/pack") == {}


@pytest.mark.parametrize("ending", ["", "\n", " "])
def test_complete_id_at_exact_limit_is_retained(ending, tmp_path, monkeypatch):
    cap = 32
    tag = " * @id cpp/owned"
    query = tmp_path / "Owned.ql"
    query.write_text(" " * (cap - len(tag)) + tag + ending)
    monkeypatch.setattr(resolver, "_pack_roots", lambda _: [tmp_path])
    monkeypatch.setattr(resolver, "_HEADER_READ_BYTES", cap)
    assert resolver._index_pack("owned/pack") == {"cpp/owned": str(query)}


def test_exact_limit_remains_character_count_for_unicode(tmp_path, monkeypatch):
    cap = 32
    opening = "/**\né\n"
    tag = " * @id cpp/owned"
    query = tmp_path / "Owned.ql"
    query.write_text(opening + " " * (cap - len(opening) - len(tag))
                     + tag + "\n */\n", encoding="utf-8")
    monkeypatch.setattr(resolver, "_pack_roots", lambda _: [tmp_path])
    monkeypatch.setattr(resolver, "_HEADER_READ_BYTES", cap)
    assert resolver._index_pack("owned/pack") == {"cpp/owned": str(query)}


def test_complete_token_beyond_limit_is_not_admitted(tmp_path, monkeypatch):
    cap = 32
    tag = " * @id cpp/owned"
    query = tmp_path / "Owned.ql"
    query.write_text(" " * (cap - len(tag) + 1) + tag + "\n")
    monkeypatch.setattr(resolver, "_pack_roots", lambda _: [tmp_path])
    monkeypatch.setattr(resolver, "_HEADER_READ_BYTES", cap)
    assert resolver._index_pack("owned/pack") == {}


def test_late_tag_remains_outside_header_admission(tmp_path, monkeypatch):
    cap = 32
    query = tmp_path / "Owned.ql"
    query.write_text(" " * cap + " * @id cpp/late\n")
    monkeypatch.setattr(resolver, "_pack_roots", lambda _: [tmp_path])
    monkeypatch.setattr(resolver, "_HEADER_READ_BYTES", cap)
    assert resolver._index_pack("owned/pack") == {}

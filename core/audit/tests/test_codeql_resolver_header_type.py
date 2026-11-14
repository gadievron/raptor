"""Query headers admit regular files without reading FIFO content."""

import os

import pytest

import core.audit.codeql_query_resolver as resolver


def test_fifo_query_refused_before_ordinary_text_open(tmp_path, monkeypatch):
    if not hasattr(os, "mkfifo"):
        pytest.skip("owned FIFO fixture unavailable")
    query = tmp_path / "Owned.ql"
    os.mkfifo(query)
    sibling = tmp_path / "Regular.ql"
    sibling.write_text(" * @id cpp/owned\n")
    monkeypatch.setattr(resolver, "_pack_roots", lambda _: [tmp_path])

    def forbidden_open(*args, **kwargs):
        raise AssertionError("FIFO must not reach ordinary text open")

    monkeypatch.setattr(resolver, "open", forbidden_open, raising=False)
    assert resolver._index_pack("owned/pack") == {"cpp/owned": str(sibling)}


def test_regular_query_header_retains_unicode_and_prefix_limit(tmp_path, monkeypatch):
    query = tmp_path / "Owned.ql"
    query.write_text("é\n * @id cpp/owned\n" + "x" * 100, encoding="utf-8")
    monkeypatch.setattr(resolver, "_pack_roots", lambda _: [tmp_path])
    monkeypatch.setattr(resolver, "_HEADER_READ_BYTES", 32)
    assert resolver._index_pack("owned/pack") == {"cpp/owned": str(query)}
    query.write_text("é" * 32 + "\n * @id cpp/late\n", encoding="utf-8")
    assert resolver._index_pack("owned/pack") == {}


def test_query_symlink_to_regular_preserves_existing_following(tmp_path, monkeypatch):
    target = tmp_path / "owned.txt"
    target.write_text(" * @id cpp/owned\n")
    link = tmp_path / "Alias.ql"
    link.symlink_to(target)
    monkeypatch.setattr(resolver, "_pack_roots", lambda _: [tmp_path])
    assert resolver._index_pack("owned/pack") == {"cpp/owned": str(link)}


def test_invalid_utf8_header_preserves_replacement_decode(tmp_path, monkeypatch):
    query = tmp_path / "Owned.ql"
    query.write_bytes(b"\xff\r\n * @id cpp/owned\r\n")
    monkeypatch.setattr(resolver, "_pack_roots", lambda _: [tmp_path])
    assert resolver._index_pack("owned/pack") == {"cpp/owned": str(query)}

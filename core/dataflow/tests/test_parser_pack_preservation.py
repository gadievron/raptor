"""Malformed merge-in-place inputs cannot become empty replacement packs."""

import json

import pytest

from core.dataflow import parser_pack_harvest as harvest


@pytest.mark.parametrize("content", [
    "{", "null", "[]", '{"entries": null}',
    '{"entries": {}}', '{"entries": "inert"}',
])
def test_existing_malformed_pack_is_refused_without_write(tmp_path, monkeypatch, content):
    pack_path = tmp_path / "owned-pack.json"
    pack_path.write_text(content, encoding="utf-8")
    before = pack_path.read_bytes()
    sources = tmp_path / "owned-sources.json"
    sources.write_text('{"sources": []}', encoding="utf-8")
    writes = []
    monkeypatch.setattr(harvest, "write_pack", lambda *args: writes.append(args))
    with pytest.raises(ValueError):
        harvest.main(["--sources", str(sources), "--pack", str(pack_path)])
    assert writes == []
    assert pack_path.read_bytes() == before


def test_valid_existing_pack_reaches_writer_with_entries_and_metadata(tmp_path, monkeypatch):
    pack_path = tmp_path / "owned-pack.json"
    original = {
        "pack": "parser_apis", "schema": harvest.PACK_SCHEMA,
        "entries": [{"name": "owned_parser", "library": "inert",
                     "provenance": ["legacy-catalog"], "cves": []}],
        "fixture_metadata": "preserve",
    }
    pack_path.write_text(json.dumps(original), encoding="utf-8")
    sources = tmp_path / "owned-sources.json"
    sources.write_text('{"sources": []}', encoding="utf-8")
    writes = []
    monkeypatch.setattr(harvest, "write_pack", lambda *args: writes.append(args))
    assert harvest.main(["--sources", str(sources), "--pack", str(pack_path)]) == 0
    assert writes == [(original, pack_path)]


def test_absent_pack_still_initialises_empty_skeleton(tmp_path):
    pack_path = tmp_path / "absent.json"
    result = harvest.load_pack(pack_path)
    assert result == {"pack": "parser_apis", "schema": harvest.PACK_SCHEMA, "entries": []}
    assert not pack_path.exists()


def test_existing_object_without_entries_retains_compatibility(tmp_path):
    pack_path = tmp_path / "owned-empty-object.json"
    pack_path.write_text("{}", encoding="utf-8")
    assert harvest.load_pack(pack_path) == {
        "pack": "parser_apis", "schema": harvest.PACK_SCHEMA, "entries": [],
    }
    assert pack_path.read_text(encoding="utf-8") == "{}"

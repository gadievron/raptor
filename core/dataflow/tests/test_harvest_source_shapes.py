"""Harvest configuration patterns are arrays, never string characters."""

import json

import pytest

from core.dataflow.parser_pack_harvest import load_sources


@pytest.mark.parametrize("patterns", ["^OWN_", {"^OWN_": True}, ["^OWN_", 1], [""]])
def test_malformed_pattern_collection_is_refused(tmp_path, patterns):
    path = tmp_path / "owned-source-config.json"
    path.write_text(json.dumps({"sources": [{
        "library": "inert", "api_patterns": patterns,
    }]}), encoding="utf-8")
    with pytest.raises(ValueError, match="api_patterns"):
        load_sources(path)


def test_valid_pattern_array_retains_regex_boundaries(tmp_path):
    path = tmp_path / "owned-source-config.json"
    path.write_text(json.dumps({"sources": [{
        "library": "inert", "api_patterns": ["^OWN_", "^OTHER_"],
    }]}), encoding="utf-8")
    source, = load_sources(path)
    assert source.api_patterns == ("^OWN_", "^OTHER_")
    patterns = source.compiled_patterns()
    assert any(p.search("OWN_parse") for p in patterns)
    assert not any(p.search("unrelated_W_name") for p in patterns)

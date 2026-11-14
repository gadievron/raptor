"""Cached edge paths obey the same string contract as caller/callee."""

import hashlib
import json
from pathlib import Path

import pytest

from core.analysis import binary_oracle_edges as edges


MISSING = object()


@pytest.fixture
def owned_cache(tmp_path, monkeypatch):
    marker = tmp_path / "marker.txt"
    raw = b"owned edge path marker\n"
    marker.write_bytes(raw)
    cache = tmp_path / "cache.json"
    original_hash = edges._content_hash
    hashes = []

    def owned_hash(path):
        assert Path(path) == marker
        hashes.append(Path(path))
        return original_hash(path)

    def forbidden(*args, **kwargs):
        pytest.fail("direct cache-row test entered binary processing")

    monkeypatch.setattr(edges, "_content_hash", owned_hash)
    for name in ("_identity_cache_key", "_try_graph_store", "extract_direct_call_edges"):
        monkeypatch.setattr(edges, name, forbidden)

    def load(path_value):
        row = {"caller": "row-caller", "callee": "row-callee"}
        if path_value is not MISSING:
            row["binary_path"] = path_value
        document = {
            "version": edges._EDGE_CACHE_VERSION,
            "binary_path": str(marker),
            "binary_sha256": hashlib.sha256(raw).hexdigest(),
            "edges": [row, {"caller": "healthy-caller", "callee": "healthy-callee"}],
        }
        payload = json.dumps(document).encode()
        cache.write_bytes(payload)
        result = edges._load_cached_index(cache, str(marker))
        assert hashes == [marker]
        assert marker.read_bytes() == raw
        assert cache.read_bytes() == payload
        assert result is not None
        return result, marker

    return load


@pytest.mark.parametrize("path_value", [7, True, {"marker": "path"}, ["marker"]])
def test_non_string_row_path_is_skipped(owned_cache, path_value):
    result, marker = owned_cache(path_value)
    assert result.edges == [edges.BinaryCallEdge("healthy-caller", "healthy-callee", str(marker))]
    assert result.callees == {"healthy-callee"}


@pytest.mark.parametrize("path_value", [MISSING, None, False, 0, ""])
def test_existing_falsy_path_fallback_remains(owned_cache, path_value):
    result, marker = owned_cache(path_value)
    assert result.edges == [
        edges.BinaryCallEdge("row-caller", "row-callee", str(marker)),
        edges.BinaryCallEdge("healthy-caller", "healthy-callee", str(marker)),
    ]
    assert result.callees == {"row-callee", "healthy-callee"}


def test_explicit_string_row_path_is_preserved(owned_cache):
    result, marker = owned_cache("retained-path")
    assert result.edges == [
        edges.BinaryCallEdge("row-caller", "row-callee", "retained-path"),
        edges.BinaryCallEdge("healthy-caller", "healthy-callee", str(marker)),
    ]
    assert result.callees == {"row-callee", "healthy-callee"}

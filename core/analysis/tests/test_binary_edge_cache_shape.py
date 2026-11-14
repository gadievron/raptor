"""Malformed edge-cache collection shapes degrade to misses."""

import hashlib
import json
from pathlib import Path

import pytest

from core.analysis import binary_oracle_edges as edges


MISSING = object()


@pytest.fixture
def owned_cache(tmp_path, monkeypatch):
    marker = tmp_path / "marker.txt"
    raw = b"owned cache binding marker\n"
    marker.write_bytes(raw)
    cache = tmp_path / "cache.json"
    original_hash = edges._content_hash
    hashes = []

    def owned_hash(path):
        assert Path(path) == marker
        hashes.append(Path(path))
        return original_hash(path)

    def forbidden(*args, **kwargs):
        pytest.fail("direct cache-load test entered binary processing")

    monkeypatch.setattr(edges, "_content_hash", owned_hash)
    for name in ("_identity_cache_key", "_try_graph_store", "extract_direct_call_edges"):
        monkeypatch.setattr(edges, name, forbidden)

    def load(records):
        document = {
            "version": edges._EDGE_CACHE_VERSION,
            "binary_path": str(marker),
            "binary_sha256": hashlib.sha256(raw).hexdigest(),
        }
        if records is not MISSING:
            document["edges"] = records
        payload = json.dumps(document).encode()
        cache.write_bytes(payload)
        result = edges._load_cached_index(cache, str(marker))
        assert hashes == [marker]
        assert marker.read_bytes() == raw
        assert cache.read_bytes() == payload
        return result, marker

    return load


@pytest.mark.parametrize("records", [7, True, None, False, 0, "marker", {}, ""])
def test_non_list_edges_are_cache_miss(owned_cache, records):
    result, _ = owned_cache(records)
    assert result is None


def test_empty_edges_remain_valid(owned_cache):
    result, marker = owned_cache([])
    assert result is not None
    assert result.binary_path == str(marker)
    assert result.edges == []
    assert result.callees == set()


def test_missing_edges_preserve_empty_cache_handling(owned_cache):
    result, _ = owned_cache(MISSING)
    assert result is not None
    assert result.edges == []
    assert result.callees == set()


def test_valid_edge_preserves_path_fallback(owned_cache):
    result, marker = owned_cache([{"caller": "caller", "callee": "callee"}])
    assert result is not None
    assert result.edges == [edges.BinaryCallEdge("caller", "callee", str(marker))]
    assert result.callees == {"callee"}


def test_list_row_tolerance_remains_unchanged(owned_cache):
    result, marker = owned_cache([None, 42, {"caller": "caller", "callee": "callee"}])
    assert result is not None
    assert result.edges == [edges.BinaryCallEdge("caller", "callee", str(marker))]
    assert result.callees == {"callee"}

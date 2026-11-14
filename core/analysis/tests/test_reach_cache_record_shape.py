"""Cache record containers retain their JSON-array shape."""

import json

import pytest

from core.analysis import _reach_cache
from core.analysis.reachability import _AdjacencyIndex


@pytest.fixture
def owned_cache(tmp_path, monkeypatch):
    root = tmp_path / "reach"
    root.mkdir(mode=0o700)
    monkeypatch.setattr(_reach_cache, "_CACHE_DIR", root)
    fingerprint = "9" * 64
    path = _reach_cache._cache_path_for(fingerprint)
    assert path is not None

    def load(field, value):
        document = _reach_cache._index_to_jsonable(_AdjacencyIndex())
        document[field] = value
        payload = _reach_cache._HEADER_MAGIC + json.dumps(document).encode()
        path.write_bytes(payload)
        path.chmod(0o600)
        restored = _reach_cache.load_index(fingerprint)
        assert path.read_bytes() == payload
        return restored

    return load


@pytest.mark.parametrize("record", ["Am", {"A": None, "m": None}], ids=["string", "object"])
def test_non_array_override_record_is_miss(owned_cache, record):
    assert owned_cache("override_methods", [record]) is None


def test_array_override_record_remains_valid(owned_cache):
    restored = owned_cache("override_methods", [["Marker", "method"]])
    assert restored is not None
    assert restored.override_methods == {("Marker", "method")}


def test_scalar_test_path_entries_remain_valid(owned_cache):
    restored = owned_cache("test_paths", ["tests/owned_marker.py"])
    assert restored is not None
    assert restored.test_paths == frozenset({"tests/owned_marker.py"})

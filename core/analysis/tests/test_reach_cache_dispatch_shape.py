"""Reject malformed dispatch flags at the owned cache-load boundary."""

import json

import pytest

from core.analysis import _reach_cache
from core.analysis.reachability import InternalFunction, _AdjacencyIndex


@pytest.fixture
def owned_entry(tmp_path, monkeypatch):
    root = tmp_path / "reach"
    root.mkdir(mode=0o700)
    monkeypatch.setattr(_reach_cache, "_CACHE_DIR", root)
    fingerprint = "7" * 64
    path = _reach_cache._cache_path_for(fingerprint)
    assert path is not None

    def write(flag):
        document = _reach_cache._index_to_jsonable(_AdjacencyIndex())
        document["has_method_dispatch"] = [[["owned.py", "marker", 1], flag]]
        payload = _reach_cache._HEADER_MAGIC + json.dumps(document).encode()
        path.write_bytes(payload)
        path.chmod(0o600)
        return fingerprint, path, payload

    return write


@pytest.mark.parametrize("flag", ["false", "true", 0, 1, None, [], {}, [False]])
def test_non_boolean_dispatch_flag_is_cache_miss(owned_entry, flag):
    fingerprint, path, payload = owned_entry(flag)
    assert _reach_cache.load_index(fingerprint) is None
    assert path.read_bytes() == payload


@pytest.mark.parametrize("flag", [False, True])
def test_boolean_dispatch_flag_round_trips(owned_entry, flag):
    fingerprint, path, payload = owned_entry(flag)
    restored = _reach_cache.load_index(fingerprint)
    assert restored is not None
    node = InternalFunction(file_path="owned.py", name="marker", line=1)
    assert restored.has_method_dispatch == {node: flag}
    assert restored.has_method_dispatch[node] is flag
    assert path.read_bytes() == payload

"""Nested JSON collections must retain their writer-produced list shape."""

import json

import pytest

from core.analysis import _reach_cache
from core.analysis.reachability import InternalFunction, _AdjacencyIndex


NODE = ["owned.py", "marker", 1]
ROWS = {
    "forward": [NODE, None],
    "reverse": ["external.marker", None],
    "uncertain_tail_paths": ["marker", None],
    "masked_file_callers": ["owned.py", "wildcard-import", None],
    "method_match": ["marker", None],
    "uncertain_callees": [NODE, None],
    "definitions": ["owned.py", "marker", None],
    "class_bases": ["owned.py", "Marker", None],
    "call_lines": [NODE, "external.marker", None],
}


@pytest.fixture
def owned_cache(tmp_path, monkeypatch):
    root = tmp_path / "reach"
    root.mkdir(mode=0o700)
    monkeypatch.setattr(_reach_cache, "_CACHE_DIR", root)
    fingerprint = "8" * 64
    path = _reach_cache._cache_path_for(fingerprint)
    assert path is not None

    def load(field, collection):
        document = _reach_cache._index_to_jsonable(_AdjacencyIndex())
        row = [*ROWS[field][:-1], collection]
        document[field] = [row]
        payload = _reach_cache._HEADER_MAGIC + json.dumps(document).encode()
        path.write_bytes(payload)
        path.chmod(0o600)
        result = _reach_cache.load_index(fingerprint)
        assert path.read_bytes() == payload
        return result

    return load


@pytest.mark.parametrize("field", ROWS)
@pytest.mark.parametrize("collection", ["", {}], ids=["string", "object"])
def test_non_list_nested_collection_is_miss(owned_cache, field, collection):
    assert owned_cache(field, collection) is None


def test_callee_name_string_is_not_split_into_characters(owned_cache):
    assert owned_cache("uncertain_callees", "marker.call") is None


@pytest.mark.parametrize("field", ROWS)
def test_empty_nested_list_remains_valid(owned_cache, field):
    restored = owned_cache(field, [])
    assert restored is not None
    node = InternalFunction(file_path="owned.py", name="marker", line=1)
    expected = {
        "forward": {node: set()},
        "reverse": None,
        "uncertain_tail_paths": {"marker": set()},
        "masked_file_callers": {"owned.py": ("wildcard-import", ())},
        "method_match": {"marker": set()},
        "uncertain_callees": {node: set()},
        "definitions": {("owned.py", "marker"): set()},
        "class_bases": {("owned.py", "Marker"): ()},
        "call_lines": None,
    }
    from core.analysis.reachability import ExternalFunction

    external = ExternalFunction(qualified_name="external.marker")
    expected["reverse"] = {external: set()}
    expected["call_lines"] = {(node, external): ()}
    assert getattr(restored, field) == expected[field]

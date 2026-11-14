"""Build-ID path validation consumes the entire supplied identifier."""

import pytest

from core.analysis import binary_oracle_edges as edges


@pytest.fixture(autouse=True)
def no_binary_work(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("direct cache-path test entered binary processing")

    for name in ("_identity_cache_key", "_content_hash", "_try_graph_store",
                 "extract_direct_call_edges"):
        monkeypatch.setattr(edges, name, forbidden)


@pytest.mark.parametrize(
    "build_id",
    ["a" * 8 + "\n", "a" * 128 + "\n", "a" * 8 + "\r\n",
     "a" * 4 + "\n" + "a" * 4, "a" * 8 + "\x00", "a" * 7, "a" * 129],
    ids=["min-lf", "max-lf", "crlf", "embedded-lf", "nul", "short", "long"],
)
def test_invalid_id_refused_before_root_lookup(monkeypatch, build_id):
    def forbidden_root():
        pytest.fail("invalid build ID reached cache-root lookup")

    monkeypatch.setattr(edges, "_edge_cache_dir", forbidden_root)
    assert edges._cache_path_for(build_id) is None


@pytest.mark.parametrize("build_id", ["01234567", "deadbeef" * 5, "f" * 128])
def test_valid_id_constructs_owned_path(tmp_path, monkeypatch, build_id):
    root = tmp_path / "owned-cache"
    calls = []

    def owned_root():
        calls.append(root)
        return root

    monkeypatch.setattr(edges, "_edge_cache_dir", owned_root)
    assert edges._cache_path_for(build_id) == root / (build_id + ".json")
    assert calls == [root]
    assert not root.exists()

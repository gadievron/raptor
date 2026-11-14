"""Fingerprint validation consumes the entire supplied string."""

import pytest

from core.analysis import _reach_cache


@pytest.mark.parametrize(
    "fingerprint",
    ["a" * 64 + "\n", "a" * 64 + "\r\n", "a" * 32 + "\n" + "a" * 32,
     "\n" + "a" * 64, "a" * 64 + " ", "a" * 64 + "\x00"],
    ids=["trailing-lf", "trailing-crlf", "embedded-lf", "leading-lf", "space", "nul"],
)
def test_invalid_extent_refused_before_cache_root(monkeypatch, fingerprint):
    def forbidden_root():
        pytest.fail("malformed fingerprint reached cache-root lookup")

    monkeypatch.setattr(_reach_cache, "_cache_dir", forbidden_root)
    assert _reach_cache._cache_path_for(fingerprint) is None


@pytest.mark.parametrize("fingerprint", ["0" * 64, "0123456789abcdef" * 4])
def test_exact_fingerprint_constructs_owned_path(tmp_path, monkeypatch, fingerprint):
    root = tmp_path / "owned-cache"
    calls = []

    def owned_root():
        calls.append(root)
        return root

    monkeypatch.setattr(_reach_cache, "_cache_dir", owned_root)
    assert _reach_cache._cache_path_for(fingerprint) == (
        root / (fingerprint + _reach_cache._CACHE_SUFFIX)
    )
    assert calls == [root]
    assert not root.exists()

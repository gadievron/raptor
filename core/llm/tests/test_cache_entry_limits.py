"""Bad entry-count limits must neither crash caching nor wipe the cache."""

import os
from types import SimpleNamespace
import pytest
from core.llm import client


@pytest.mark.parametrize(
    "limit", [-1, -100, 1.5, "2", True, False, 0.0, float("nan"), float("inf")]
)
def test_invalid_entry_limit_uses_bounded_default(tmp_path, monkeypatch, limit):
    monkeypatch.setattr(client, "DEFAULT_CACHE_MAX_ENTRIES", 2, raising=False)
    paths = []
    for i in range(4):
        path = tmp_path / f"{i}.json"
        path.write_text("cached")
        os.utime(path, (1000 + i,) * 2)
        paths.append(path)
    owner = SimpleNamespace(
        config=SimpleNamespace(cache_dir=tmp_path, cache_max_entries=limit)
    )
    client.LLMClient._maybe_evict_cache(owner)
    assert [path.exists() for path in paths] == [False, False, True, True]


@pytest.mark.parametrize("limit", [None, 0])
def test_explicit_unlimited_entry_limit_still_keeps_all_files(tmp_path, limit):
    for i in range(4):
        (tmp_path / f"{i}.json").write_text("cached")
    owner = SimpleNamespace(
        config=SimpleNamespace(cache_dir=tmp_path, cache_max_entries=limit)
    )
    client.LLMClient._maybe_evict_cache(owner)
    assert len(list(tmp_path.iterdir())) == 4

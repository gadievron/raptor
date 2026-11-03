"""Streaming cache writes preserve the format and atomic size limit."""
import json
import os
import stat

import pytest

from core.analysis import _reach_cache as cache
from core.analysis.reachability import InternalFunction, ExternalFunction, _AdjacencyIndex


def _index():
    fn = InternalFunction(file_path="café.py", name="处理", line=42)
    dst = ExternalFunction(qualified_name="lib.é")
    return _AdjacencyIndex(
        forward={fn: {dst}}, reverse={dst: {fn}},
        definitions={(fn.file_path, fn.name): {fn}},
        call_lines={(fn, dst): (42, 57)},
        test_paths=frozenset(f"tests/{n:05d}.py" for n in range(9000)),
    )


def _legacy_bytes(idx):
    return cache._HEADER_MAGIC + json.dumps(
        cache._index_to_jsonable(idx), separators=(",", ":"),
    ).encode("utf-8")


@pytest.mark.parametrize("slack", [-1, 0, 1])
def test_exact_size_boundary(tmp_path, monkeypatch, slack, caplog):
    monkeypatch.setattr(cache, "_CACHE_DIR", tmp_path)
    idx = _index()
    expected = _legacy_bytes(idx)
    monkeypatch.setattr(cache, "_MAX_INDEX_BYTES", len(expected) + slack)
    fp = "a" * 64
    path = tmp_path / (fp + ".json")
    path.write_bytes(b"existing entry")
    evictions = []
    monkeypatch.setattr(cache, "_evict_oldest", lambda: evictions.append(True))
    cache.save_index(fp, idx)
    assert not list(tmp_path.glob(".reach-tmp-*"))
    if slack < 0:
        assert path.read_bytes() == b"existing entry"
        assert not evictions
        assert "past the loader's" in caplog.text
    else:
        assert path.read_bytes() == expected
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert cache.load_index(fp) == idx
        assert evictions == [True]


def test_late_oversize_rolls_back_after_writing_chunks(tmp_path, monkeypatch):
    monkeypatch.setattr(cache, "_CACHE_DIR", tmp_path)
    idx = _index()
    monkeypatch.setattr(cache, "_MAX_INDEX_BYTES", len(_legacy_bytes(idx)) - 1)
    fp = "b" * 64
    path = tmp_path / (fp + ".json")
    path.write_bytes(b"old")
    real_write = os.write
    sizes = []

    def recording_write(fd, data):
        sizes.append(len(data))
        return real_write(fd, data)

    monkeypatch.setattr(os, "write", recording_write)
    cache.save_index(fp, idx)
    assert sum(sizes) > 64 * 1024
    assert path.read_bytes() == b"old"
    assert not list(tmp_path.glob(".reach-tmp-*"))


def test_streamed_tokens_survive_short_writes(tmp_path, monkeypatch):
    monkeypatch.setattr(cache, "_CACHE_DIR", tmp_path)
    idx = _index()
    expected = _legacy_bytes(idx)
    real_write = os.write

    def short_write(fd, data):
        return real_write(fd, data[:997])

    monkeypatch.setattr(os, "write", short_write)
    cache.save_index("c" * 64, idx)
    assert (tmp_path / ("c" * 64 + ".json")).read_bytes() == expected
    assert not list(tmp_path.glob(".reach-tmp-*"))

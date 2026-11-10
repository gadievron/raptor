"""Optional cache cleanup retains operation errors and fresh close policy."""
import os
from types import SimpleNamespace

import pytest

from core.analysis import _reach_cache as cache


@pytest.fixture
def cache_io(tmp_path, monkeypatch):
    path = tmp_path / "inert.cache"
    path.write_bytes(b"not a cache")
    path.chmod(0o600)
    state = {"live": set(), "closes": 0, "primary": None, "cleanup": None}

    def opened(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        state["live"].add(fd)
        return fd

    def info(fd):
        result = os.fstat(fd)
        if state["primary"] is not None:
            raise state["primary"]
        return result

    def close(fd):
        os.close(fd)
        state["live"].remove(fd)
        state["closes"] += 1
        if state["cleanup"] is not None:
            raise state["cleanup"]

    monkeypatch.setattr(cache, "_cache_path_for", lambda _fingerprint: path)
    monkeypatch.setattr(cache, "os", SimpleNamespace(
        **{**vars(os), "open": opened, "fstat": info, "close": close}))
    try:
        yield state
    finally:
        for fd in state["live"]:
            os.close(fd)


@pytest.mark.parametrize("primary_type", [MemoryError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt, SystemExit])
def test_active_metadata_error_survives_cleanup(cache_io, primary_type, close_type):
    primary = primary_type("after real metadata lookup")
    cache_io["primary"] = primary
    cache_io["cleanup"] = close_type("after real close")
    with pytest.raises(primary_type) as raised:
        cache.load_index("inert-fingerprint")
    assert raised.value is primary
    assert cache_io["closes"] == 1
    assert not cache_io["live"]


@pytest.mark.parametrize("close_type", [KeyboardInterrupt, SystemExit])
def test_fresh_close_interrupt_remains_visible(cache_io, close_type):
    cleanup = close_type("after real close")
    cache_io["cleanup"] = cleanup
    with pytest.raises(close_type) as raised:
        cache.load_index("inert-fingerprint")
    assert raised.value is cleanup
    assert cache_io["closes"] == 1
    assert not cache_io["live"]


def test_close_io_failure_remains_best_effort(cache_io):
    cache_io["cleanup"] = OSError("after real close")
    assert cache.load_index("inert-fingerprint") is None
    assert cache_io["closes"] == 1
    assert not cache_io["live"]

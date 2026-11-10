"""Bounded private cache-header cleanup; no maintenance walk or eviction."""
import os
from types import SimpleNamespace

import pytest

from packages.sca import cache_budget as module


@pytest.fixture
def header_io(tmp_path, monkeypatch):
    path = tmp_path / "owned.json"
    path.write_bytes(b'{"written_at":10,"ttl_seconds":5,"value":"plain"}\n')
    unit = module._Unit(path=path, size=path.stat().st_size, written=0, used=0)
    state = {"unit": unit, "site": "read", "primary": None, "cleanup": None,
             "closes": 0, "live": set(), "reads": []}

    def opened(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        state["live"].add(fd)
        return fd

    def fstat(fd):
        result = os.fstat(fd)
        if state["site"] == "metadata" and state["primary"] is not None:
            raise state["primary"]
        return result

    def read(fd, size):
        result = os.read(fd, size)
        state["reads"].append(size)
        if state["site"] == "read" and state["primary"] is not None:
            raise state["primary"]
        return result

    def close(fd):
        os.close(fd)
        state["live"].remove(fd)
        state["closes"] += 1
        if state["cleanup"] is not None:
            raise state["cleanup"]

    monkeypatch.setattr(module, "os", SimpleNamespace(
        **{**vars(os), "open": opened, "fstat": fstat, "read": read, "close": close}))
    try:
        yield state
    finally:
        for fd in state["live"]:
            os.close(fd)


def test_read_interruption_does_not_become_unknown_expiry(header_io):
    primary = KeyboardInterrupt("after native cache-header read")
    header_io.update(primary=primary, cleanup=OSError("after native close"))
    with pytest.raises(KeyboardInterrupt) as raised:
        module._expired(header_io["unit"], 20)
    assert raised.value is primary
    assert header_io["reads"] == [256]
    assert header_io["closes"] == 1
    assert not header_io["live"]


@pytest.mark.parametrize("site", ["metadata", "read"])
@pytest.mark.parametrize("primary_type", [RuntimeError, MemoryError, SystemExit])
@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt])
def test_active_header_error_keeps_identity(header_io, site, primary_type, close_type):
    primary = primary_type("after native cache-header operation")
    header_io.update(site=site, primary=primary, cleanup=close_type("after native close"))
    with pytest.raises(primary_type) as raised:
        module._expired(header_io["unit"], 20)
    assert raised.value is primary
    assert header_io["closes"] == 1
    assert not header_io["live"]


@pytest.mark.parametrize("site", ["metadata", "read"])
@pytest.mark.parametrize("primary_type", [OSError, ValueError, OverflowError])
def test_handled_header_failures_still_return_false(header_io, site, primary_type):
    header_io.update(site=site, primary=primary_type("after native operation"))
    assert module._expired(header_io["unit"], 20) is False
    assert header_io["closes"] == 1
    assert not header_io["live"]


@pytest.mark.parametrize("site", ["metadata", "read"])
@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt])
def test_handled_io_retains_fresh_close_policy(header_io, site, close_type):
    cleanup = close_type("after native close")
    header_io.update(site=site, primary=OSError("after native operation"), cleanup=cleanup)
    if close_type is OSError:
        assert module._expired(header_io["unit"], 20) is False
    else:
        with pytest.raises(KeyboardInterrupt) as raised:
            module._expired(header_io["unit"], 20)
        assert raised.value is cleanup
    assert header_io["closes"] == 1
    assert not header_io["live"]


@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt, SystemExit])
def test_native_success_retains_fresh_close_policy(header_io, close_type):
    cleanup = close_type("after native close")
    header_io["cleanup"] = cleanup
    if close_type is OSError:
        assert module._expired(header_io["unit"], 20) is False
    else:
        with pytest.raises(close_type) as raised:
            module._expired(header_io["unit"], 20)
        assert raised.value is cleanup
    assert header_io["reads"] == [256]
    assert header_io["closes"] == 1
    assert not header_io["live"]


def test_native_header_retains_expiry_result_and_read_extent(header_io):
    assert module._expired(header_io["unit"], 20) is True
    assert header_io["reads"] == [256]
    assert header_io["closes"] == 1
    assert not header_io["live"]

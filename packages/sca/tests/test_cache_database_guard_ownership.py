"""Owned-file 16-byte signature guard; no database opening or cache eviction."""
import os
from types import SimpleNamespace

import pytest

from packages.sca import cache_budget as module


@pytest.fixture
def guard_io(tmp_path, monkeypatch):
    path = tmp_path / "owned.db.json"
    path.write_bytes(b"ordinary plaintext, no database\n")
    state = {"path": path, "site": "read", "primary": None, "cleanup": None,
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


def test_read_interruption_does_not_become_protected_database(guard_io):
    primary = KeyboardInterrupt("after native signature read")
    guard_io.update(primary=primary, cleanup=OSError("after native close"))
    with pytest.raises(KeyboardInterrupt) as raised:
        module._is_database(guard_io["path"])
    assert raised.value is primary
    assert guard_io["reads"] == [16]
    assert guard_io["closes"] == 1
    assert not guard_io["live"]


@pytest.mark.parametrize("site", ["metadata", "read"])
@pytest.mark.parametrize("primary_type", [RuntimeError, MemoryError, SystemExit, ValueError])
@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt])
def test_active_signature_error_keeps_identity(guard_io, site, primary_type, close_type):
    primary = primary_type("after native signature operation")
    guard_io.update(site=site, primary=primary, cleanup=close_type("after native close"))
    with pytest.raises(primary_type) as raised:
        module._is_database(guard_io["path"])
    assert raised.value is primary
    assert guard_io["closes"] == 1
    assert not guard_io["live"]


@pytest.mark.parametrize("site", ["metadata", "read"])
def test_handled_io_still_protects_entry(guard_io, site):
    guard_io.update(site=site, primary=OSError("after native operation"))
    assert module._is_database(guard_io["path"]) is True
    assert guard_io["closes"] == 1
    assert not guard_io["live"]


@pytest.mark.parametrize("site", ["metadata", "read"])
@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt])
def test_handled_io_retains_fresh_close_policy(guard_io, site, close_type):
    cleanup = close_type("after native close")
    guard_io.update(site=site, primary=OSError("after native operation"), cleanup=cleanup)
    if close_type is OSError:
        assert module._is_database(guard_io["path"]) is True
    else:
        with pytest.raises(KeyboardInterrupt) as raised:
            module._is_database(guard_io["path"])
        assert raised.value is cleanup
    assert guard_io["closes"] == 1
    assert not guard_io["live"]


@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt, SystemExit])
def test_healthy_signature_retains_fresh_close_policy(guard_io, close_type):
    cleanup = close_type("after native close")
    guard_io["cleanup"] = cleanup
    if close_type is OSError:
        assert module._is_database(guard_io["path"]) is True
    else:
        with pytest.raises(close_type) as raised:
            module._is_database(guard_io["path"])
        assert raised.value is cleanup
    assert guard_io["reads"] == [16]
    assert guard_io["closes"] == 1
    assert not guard_io["live"]


@pytest.mark.parametrize("kind", ["ordinary", "signature", "empty"])
def test_native_bounded_header_decisions_are_retained(guard_io, kind):
    if kind == "signature":
        # A marker plus plaintext only, not a SQLite database or database parse.
        guard_io["path"].write_bytes(b"SQLite format 3\x00trailing plaintext")
    elif kind == "empty":
        guard_io["path"].write_bytes(b"")
    assert module._is_database(guard_io["path"]) is (kind != "ordinary")
    assert guard_io["reads"] == ([] if kind == "empty" else [16])
    assert guard_io["closes"] == 1
    assert not guard_io["live"]

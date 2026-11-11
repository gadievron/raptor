"""Native append cleanup retires the descriptor without replacing errors."""
import errno
import fcntl
import os
from types import SimpleNamespace

import pytest

from core.coverage import journal
from core.coverage.tests.test_journal_append import _entry
from core.testing.module_views import module_function_view


@pytest.fixture
def append_probe(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    run = tmp_path / "run"
    run.mkdir()
    state = {"opened": [], "unlocked": [], "closed": [], "writes": 0,
             "primary": None, "unlock_error": None, "close_error": None, "run": run}

    def native_open(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        state["opened"].append(fd)
        return fd

    def native_write(fd, data):
        written = os.write(fd, data)
        assert written == len(data)
        state["writes"] += 1
        if state["primary"] is not None:
            raise state["primary"]
        return written

    def native_flock(fd, operation):
        fcntl.flock(fd, operation)
        if operation == fcntl.LOCK_UN:
            state["unlocked"].append(fd)
            if state["unlock_error"] is not None:
                raise state["unlock_error"]

    def native_close(fd):
        os.close(fd)
        state["closed"].append(fd)
        if state["close_error"] is not None:
            raise state["close_error"]

    view = module_function_view(journal, bindings={
        "os": SimpleNamespace(**{**vars(os), "open": native_open,
                                  "write": native_write, "close": native_close}),
        "fcntl": SimpleNamespace(**{**vars(fcntl), "flock": native_flock}),
    })
    state["append"] = lambda: view.append_entry(run, _entry(1))
    try:
        yield state
    finally:
        for fd in state["opened"]:
            try:
                os.fstat(fd)
            except OSError as exc:
                assert exc.errno == errno.EBADF
            else:
                os.close(fd)


def assert_retired(state):
    assert len(state["opened"]) == 1
    assert state["unlocked"] == state["closed"] == state["opened"]
    assert state["writes"] == 1
    for fd in state["opened"]:
        with pytest.raises(OSError) as retired:
            os.fstat(fd)
        assert retired.value.errno == errno.EBADF
    # The native append completed before injected after-effect errors. An error
    # acknowledgement must not be interpreted as proof that no row committed.
    assert (state["run"] / journal.JOURNAL_FILENAME).read_bytes().endswith(b"\n")


@pytest.mark.parametrize("primary_type", [OSError, MemoryError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("unlock_fails", [False, True])
@pytest.mark.parametrize("close_fails", [False, True])
def test_body_error_keeps_precedence(append_probe, primary_type, unlock_fails, close_fails):
    primary = primary_type("owned native write after-effect failure")
    append_probe["primary"] = primary
    if unlock_fails:
        append_probe["unlock_error"] = OSError("owned unlock after-effect failure")
    if close_fails:
        append_probe["close_error"] = OSError("owned close after-effect failure")
    with pytest.raises(primary_type) as raised:
        append_probe["append"]()
    assert raised.value is primary
    assert_retired(append_probe)


@pytest.mark.parametrize("unlock_type", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("close_fails", [False, True])
def test_first_fresh_unlock_error_survives_close(append_probe, unlock_type, close_fails):
    failure = unlock_type("owned unlock after-effect failure")
    append_probe["unlock_error"] = failure
    if close_fails:
        append_probe["close_error"] = OSError("owned close after-effect failure")
    with pytest.raises(unlock_type) as raised:
        append_probe["append"]()
    assert raised.value is failure
    assert_retired(append_probe)


@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt, SystemExit])
def test_fresh_close_error_remains_visible(append_probe, close_type):
    failure = close_type("owned close after-effect failure")
    append_probe["close_error"] = failure
    with pytest.raises(close_type) as raised:
        append_probe["append"]()
    assert raised.value is failure
    assert_retired(append_probe)


def test_native_append_retires_healthy_resources(append_probe):
    assert append_probe["append"]() is None
    assert_retired(append_probe)

"""Failed rollback refuses acknowledgement without retrying a torn row."""
import errno
import fcntl
import os
from types import SimpleNamespace

import pytest

from core.coverage import journal
from core.coverage.tests.test_journal_append import _entry
from core.testing.module_views import module_function_view


@pytest.fixture
def rollback_probe(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    run = tmp_path / "run"
    journal.append_entry(run, _entry(1))
    path = run / journal.JOURNAL_FILENAME
    before = path.read_bytes()
    state = {"run": run, "path": path, "before": before, "opened": [],
             "writes": [], "truncates": [], "fragment": b"", "closed": [],
             "unlocked": [], "rollback_error": OSError("owned rollback refusal"),
             "cleanup_fault": None, "after_effect": False}

    def native_open(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        state["opened"].append(fd)
        return fd

    def native_write(fd, data):
        state["writes"].append(len(data))
        if len(state["writes"]) == 1:
            fragment = data[:len(data) // 2]
            assert fragment and not fragment.endswith(b"\n")
            state["fragment"] = fragment
            return os.write(fd, fragment)
        return os.write(fd, data)

    def native_truncate(fd, size):
        assert os.fstat(fd).st_size == len(before) + len(state["fragment"])
        state["truncates"].append((fd, size))
        if state["after_effect"]:
            os.ftruncate(fd, size)
        raise state["rollback_error"]

    def native_flock(fd, operation):
        fcntl.flock(fd, operation)
        if operation == fcntl.LOCK_UN:
            state["unlocked"].append(fd)
            if state["cleanup_fault"] in ("unlock", "both"):
                raise OSError("owned unlock after-effect failure")

    def native_close(fd):
        os.close(fd)
        state["closed"].append(fd)
        if state["cleanup_fault"] in ("close", "both"):
            raise OSError("owned close after-effect failure")

    view = module_function_view(journal, bindings={
        "os": SimpleNamespace(**{**vars(os), "open": native_open, "write": native_write,
                                  "ftruncate": native_truncate, "close": native_close}),
        "fcntl": SimpleNamespace(**{**vars(fcntl), "flock": native_flock}),
    })
    state["append"] = lambda: view.append_entry(run, _entry(2, body_size=8192))
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


def assert_rollback_refused(state):
    assert len(state["opened"]) == 1
    assert state["truncates"] == [(state["opened"][0], len(state["before"]))]
    assert len(state["writes"]) == 1
    assert state["unlocked"] == state["closed"] == state["opened"]
    with pytest.raises(OSError) as retired:
        os.fstat(state["opened"][0])
    assert retired.value.errno == errno.EBADF
    after = state["path"].read_bytes()
    assert after.startswith(state["before"])
    expected_tail = b"" if state["after_effect"] else state["fragment"]
    assert after == state["before"] + expected_tail


@pytest.mark.parametrize("error_type", [OSError, MemoryError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("cleanup_fault", [None, "unlock", "close", "both"])
def test_rollback_refusal_stops_retry_and_preserves_error(rollback_probe, error_type, cleanup_fault):
    failure = error_type("owned rollback refusal")
    rollback_probe["rollback_error"] = failure
    rollback_probe["cleanup_fault"] = cleanup_fault
    with pytest.raises(error_type) as raised:
        rollback_probe["append"]()
    assert raised.value is failure
    assert_rollback_refused(rollback_probe)


def test_rollback_after_effect_error_does_not_retry_or_acknowledge(rollback_probe):
    rollback_probe["after_effect"] = True
    failure = rollback_probe["rollback_error"]
    with pytest.raises(OSError) as raised:
        rollback_probe["append"]()
    assert raised.value is failure
    assert_rollback_refused(rollback_probe)

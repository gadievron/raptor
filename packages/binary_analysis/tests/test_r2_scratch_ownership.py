"""Scratch lifetime with a native owned file; no r2/child/profile execution."""
from contextlib import contextmanager
from pathlib import Path
import tempfile

import pytest

from core.run import scratch
from packages.binary_analysis import radare2_understand as consumer


@pytest.fixture
def session_io(tmp_path, monkeypatch):
    state = {"directories": [], "managers": [], "cleanups": [], "faults": {},
             "quit_error": None, "quits": 0, "spawn_calls": 0}
    native = tempfile.TemporaryFile(dir=tmp_path)

    class Handle:
        def quit(self):
            native.close()
            state["quits"] += 1
            if state["quit_error"] is not None:
                raise state["quit_error"]

    @contextmanager
    def owned_scratch(prefix):
        manager = tempfile.TemporaryDirectory(prefix=prefix, dir=tmp_path)
        index = len(state["directories"]) + 1
        state["managers"].append(manager)
        state["directories"].append(Path(manager.name))
        try:
            yield Path(manager.name)
        finally:
            manager.cleanup()
            state["cleanups"].append(index)
            if index in state["faults"]:
                raise state["faults"][index]

    def spawn(*_args):
        state["spawn_calls"] += 1
        return Handle()

    analyser = object.__new__(consumer.BinaryUnderstand)
    monkeypatch.setattr(analyser, "_spawn_r2", spawn)
    monkeypatch.setattr(scratch, "scratch_dir", owned_scratch)
    state.update(analyser=analyser, native=native)
    try:
        yield state
    finally:
        native.close()
        for manager in state["managers"]:
            manager.cleanup()


def test_quit_interrupt_does_not_skip_owned_scratch_cleanup(session_io):
    primary = KeyboardInterrupt("after owned native handle close")
    session_io["quit_error"] = primary
    with pytest.raises(KeyboardInterrupt) as raised:
        with session_io["analyser"]._sandboxed_session():
            assert len(session_io["directories"]) == 2
    assert raised.value is primary
    assert session_io["native"].closed
    assert session_io["quits"] == session_io["spawn_calls"] == 1
    assert not any(path.exists() for path in session_io["directories"])
    assert session_io["cleanups"] == [2, 1]


@pytest.mark.parametrize(("quit_type", "scratch_type"), [
    (SystemExit, None), (KeyboardInterrupt, OSError),
    (KeyboardInterrupt, KeyboardInterrupt), (SystemExit, OSError),
    (SystemExit, KeyboardInterrupt),
])
def test_quit_primary_survives_independent_scratch_failures(session_io, quit_type, scratch_type):
    primary = quit_type("after native handle close")
    session_io["quit_error"] = primary
    if scratch_type is not None:
        session_io["faults"] = {1: scratch_type("after native first scratch cleanup"),
                               2: scratch_type("after native second scratch cleanup")}
    with pytest.raises(quit_type) as raised:
        with session_io["analyser"]._sandboxed_session():
            pass
    assert raised.value is primary
    assert session_io["native"].closed
    assert session_io["quits"] == 1
    assert session_io["cleanups"] == [2, 1]
    assert not any(path.exists() for path in session_io["directories"])


@pytest.mark.parametrize("primary_type", [ValueError, KeyboardInterrupt])
@pytest.mark.parametrize("scratch_type", [None, OSError, KeyboardInterrupt])
def test_body_error_survives_scratch_cleanup(session_io, primary_type, scratch_type):
    primary = primary_type("owned context body failed")
    if scratch_type is not None:
        session_io["faults"] = {2: scratch_type("after native scratch cleanup")}
    with pytest.raises(primary_type) as raised:
        with session_io["analyser"]._sandboxed_session():
            raise primary
    assert raised.value is primary
    assert session_io["native"].closed
    assert session_io["quits"] == 1
    assert session_io["cleanups"] == [2, 1]
    assert not any(path.exists() for path in session_io["directories"])


@pytest.mark.parametrize("scratch_type", [OSError, KeyboardInterrupt])
@pytest.mark.parametrize("index", [1, 2])
def test_fresh_scratch_cleanup_error_remains_visible(session_io, scratch_type, index):
    cleanup = scratch_type("after native scratch cleanup")
    session_io["faults"] = {index: cleanup}
    with pytest.raises(scratch_type) as raised:
        with session_io["analyser"]._sandboxed_session():
            pass
    assert raised.value is cleanup
    assert session_io["native"].closed
    assert session_io["quits"] == 1
    assert session_io["cleanups"] == [2, 1]
    assert not any(path.exists() for path in session_io["directories"])


@pytest.mark.parametrize("quit_type", [OSError, RuntimeError, MemoryError])
def test_ordinary_quit_error_remains_best_effort(session_io, quit_type):
    session_io["quit_error"] = quit_type("after native handle close")
    with session_io["analyser"]._sandboxed_session():
        pass
    assert session_io["native"].closed
    assert session_io["quits"] == 1
    assert session_io["cleanups"] == [2, 1]
    assert not any(path.exists() for path in session_io["directories"])


def test_success_retires_handle_and_both_scratch_contexts(session_io):
    with session_io["analyser"]._sandboxed_session() as session:
        assert session._handle is not None
        assert all(path.is_dir() for path in session_io["directories"])
    assert session._handle is None
    assert session_io["native"].closed
    assert session_io["quits"] == session_io["spawn_calls"] == 1
    assert session_io["cleanups"] == [2, 1]
    assert not any(path.exists() for path in session_io["directories"])

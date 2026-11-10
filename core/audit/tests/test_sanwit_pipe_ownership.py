"""Native owned streams with a nonexecuting client adapter; no Docker actions."""
from contextlib import ExitStack
import io
import os
from types import SimpleNamespace

import pytest

from core.audit.sanwit import _execute as module
from core.testing.module_bindings import patch_module_attribute


@pytest.fixture
def pipe_io(tmp_path, monkeypatch):
    state = SimpleNamespace(close_errors={}, read_error=None, kill_error=None,
                            poll_error=None, callback_error=None, kills=0, polls=0,
                            waits=0, callbacks=0, spawns=0, returncode=None,
                            exit_code=0, stdout_reads=0, closes={"stdout": 0, "stderr": 0})

    class Stream(io.BufferedReader):
        def __init__(self, raw, name):
            super().__init__(raw)
            self.label = name

        def read1(self, size=-1):
            data = super().read1(size)
            if self.label == "stdout":
                state.stdout_reads += 1
                if data and state.read_error is not None:
                    raise state.read_error
            return data

        def close(self):
            was_open = not self.closed
            super().close()
            if was_open:
                state.closes[self.label] += 1
                error = state.close_errors.get(self.label)
                if error is not None:
                    raise error

    with ExitStack() as resources:
        streams = {}
        for name, data in (("stdout", b"owned output"), ("stderr", b"owned diagnostic\n")):
            path = tmp_path / name
            path.write_bytes(data)
            raw = resources.enter_context(path.open("rb", buffering=0))
            stream = Stream(raw, name)
            resources.callback(io.BufferedReader.close, stream)
            streams[name] = stream

        class Client:
            stdout = streams["stdout"]
            stderr = streams["stderr"]

            def wait(self, timeout=None):
                assert timeout is not None
                state.waits += 1
                state.returncode = state.exit_code
                return state.returncode

            def poll(self):
                state.polls += 1
                if state.poll_error is not None:
                    raise state.poll_error
                return state.returncode

            def kill(self):
                state.kills += 1
                if state.kill_error is not None:
                    raise state.kill_error
                state.returncode = -9

            def terminate(self):
                pytest.fail("small owned streams must not enter timeout/overflow termination")

        state.client = Client()

        def spawn(cmd, **kwargs):
            assert cmd == ["owned-inert-client"]
            assert kwargs == {"stdout": module.subprocess.PIPE, "stderr": module.subprocess.PIPE, "env": {}}
            state.spawns += 1
            return state.client

        def cleanup():
            state.callbacks += 1
            if state.callback_error is not None:
                raise state.callback_error

        state.cleanup = cleanup
        patch_module_attribute(monkeypatch, module, "subprocess", "Popen", spawn)
        try:
            yield state
        finally:
            live = []
            for name, stream in streams.items():
                if not stream.closed:
                    os.fstat(stream.fileno())
                    live.append(name)
            if live:
                print("owned native streams still open before fixture cleanup:", live,
                      "callback attempts:", state.callbacks, "adapter kill attempts:", state.kills)


def _run(state, callback=True):
    return module._run_capped_pipes(["owned-inert-client"], env={}, cleanup=state.cleanup if callback else None)


def _assert_retired(state, callback=True):
    assert state.spawns == 1
    assert state.stdout_reads > 0
    assert state.client.stdout.closed and state.client.stderr.closed
    assert state.closes == {"stdout": 1, "stderr": 1}
    assert state.callbacks == int(callback)


def test_stdout_close_fault_still_retires_sibling_and_callback(pipe_io):
    cleanup = OSError("after native stdout close")
    pipe_io.close_errors["stdout"] = cleanup
    with pytest.raises(OSError) as raised:
        _run(pipe_io)
    assert raised.value is cleanup
    _assert_retired(pipe_io)
    assert pipe_io.polls == 1 and pipe_io.kills == 0


@pytest.mark.parametrize("primary_type", [KeyboardInterrupt, SystemExit, RuntimeError, MemoryError])
@pytest.mark.parametrize("site", ["stdout", "stderr", "poll", "callback"])
def test_operation_error_survives_all_cleanup_attempts(pipe_io, primary_type, site):
    primary = primary_type("after native owned read")
    pipe_io.read_error = primary
    cleanup = OSError("owned cleanup failed")
    if site in {"stdout", "stderr"}:
        pipe_io.close_errors[site] = cleanup
    elif site == "poll":
        pipe_io.poll_error = cleanup
    else:
        pipe_io.callback_error = cleanup
    with pytest.raises(primary_type) as raised:
        _run(pipe_io)
    assert raised.value is primary
    _assert_retired(pipe_io)
    assert pipe_io.kills == (0 if site == "poll" else 1)


@pytest.mark.parametrize("site", ["stdout", "stderr", "poll", "callback"])
def test_fresh_cleanup_error_remains_visible(pipe_io, site):
    cleanup = RuntimeError("owned cleanup failed")
    if site in {"stdout", "stderr"}:
        pipe_io.close_errors[site] = cleanup
    elif site == "poll":
        pipe_io.poll_error = cleanup
    else:
        pipe_io.callback_error = cleanup
    with pytest.raises(RuntimeError) as raised:
        _run(pipe_io)
    assert raised.value is cleanup
    _assert_retired(pipe_io)


def test_first_fresh_close_failure_keeps_precedence(pipe_io):
    first = OSError("after native stdout close")
    pipe_io.close_errors.update(stdout=first, stderr=MemoryError("after native stderr close"))
    pipe_io.poll_error = RuntimeError("adapter poll failed")
    pipe_io.callback_error = KeyboardInterrupt("cleanup recorder failed")
    with pytest.raises(OSError) as raised:
        _run(pipe_io)
    assert raised.value is first
    _assert_retired(pipe_io)


@pytest.mark.parametrize("error_type", [OSError, ValueError])
def test_handled_read_error_retains_result_and_cleanup(pipe_io, error_type):
    pipe_io.read_error = error_type("after native owned read")
    result = _run(pipe_io)
    assert not result.ok
    assert result.reason == f"docker execution failed: {error_type.__name__}"
    assert pipe_io.kills == 1
    _assert_retired(pipe_io)


def test_handler_kill_error_keeps_identity_through_cleanup(pipe_io):
    primary = RuntimeError("nonexecuting adapter kill failed")
    pipe_io.read_error = OSError("after native owned read")
    pipe_io.kill_error = primary
    pipe_io.close_errors["stdout"] = OSError("after native stdout close")
    with pytest.raises(RuntimeError) as raised:
        _run(pipe_io)
    assert raised.value is primary
    assert pipe_io.kills == 2
    _assert_retired(pipe_io)


@pytest.mark.parametrize("exit_code", [0, 5])
@pytest.mark.parametrize("callback", [False, True])
def test_native_streams_keep_output_and_exit_results(pipe_io, exit_code, callback):
    pipe_io.exit_code = exit_code
    result = _run(pipe_io, callback)
    assert result.ok == (exit_code == 0)
    if result.ok:
        assert result.stdout == "owned output"
    else:
        assert result.reason == "probe exited 5: owned diagnostic"
    assert pipe_io.kills == 0
    _assert_retired(pipe_io, callback)

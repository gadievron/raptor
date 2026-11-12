"""Actual staging copies preserve failure precedence across both streams."""
import builtins
import io
import shutil
from types import SimpleNamespace

import pytest

from core.container import compose


@pytest.fixture
def copy(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    payload = b"owned build context bytes\n"
    (source / "input").write_bytes(payload)
    destination = tmp_path / "staging"
    state = SimpleNamespace(primary=None, phase="read", cleanup=None,
                            cleanup_at="input", streams=[], closes=[],
                            reads=[], writes=[], payload=payload,
                            source=source, destination=destination)
    native_open = compose.open_regular_beneath

    class Input(io.BufferedReader):
        def read(self, size=-1):
            data = super().read(size)
            state.reads.append(data)
            if state.primary is not None and state.phase == "read":
                raise state.primary
            return data

        def close(self):
            if self.closed:
                return super().close()
            super().close()
            state.closes.append("input")
            if state.cleanup is not None and state.cleanup_at == "input":
                raise state.cleanup

    class Output(io.BufferedWriter):
        def write(self, data):
            count = super().write(data)
            state.writes.append(bytes(data))
            if state.primary is not None and state.phase == "write":
                raise state.primary
            return count

        def close(self):
            if self.closed:
                return super().close()
            super().close()
            state.closes.append("output")
            if state.cleanup is not None and state.cleanup_at == "output":
                raise state.cleanup

    def open_input(root, rel, mode):
        assert root == source and str(rel) == "input" and mode == "rb"
        native = native_open(root, rel, mode)
        assert native is not None
        wrapped = Input(native)
        state.streams.extend((native, wrapped))
        return wrapped

    def open_output(path, mode):
        assert path == str(destination / "input") and mode == "xb"
        native = builtins.open(path, mode)
        wrapped = Output(native)
        state.streams.extend((native, wrapped))
        return wrapped

    monkeypatch.setattr(compose, "open_regular_beneath", open_input)
    monkeypatch.setattr(compose, "open", open_output, raising=False)
    state.run = lambda: compose._copy_staging_tree(source, destination)
    try:
        yield state
    finally:
        for stream in reversed(state.streams):
            if not stream.closed:
                if isinstance(stream, Output):
                    io.BufferedWriter.close(stream)
                elif isinstance(stream, Input):
                    io.BufferedReader.close(stream)
                else:
                    stream.close()
        assert (source / "input").read_bytes() == payload


def assert_retired(state):
    assert state.reads and state.reads[0] == state.payload
    assert state.closes == ["output", "input"]
    assert len(state.streams) == 4 and all(stream.closed for stream in state.streams)


@pytest.mark.parametrize("phase", ["read", "write"])
@pytest.mark.parametrize("cleanup_at", ["input", "output"])
def test_copy_cancellation_survives_consumed_close(copy, phase, cleanup_at):
    copy.phase, copy.cleanup_at = phase, cleanup_at
    copy.primary = KeyboardInterrupt("after native staging copy operation")
    copy.cleanup = OSError("after native staging stream close")
    with pytest.raises(KeyboardInterrupt) as caught:
        copy.run()
    assert caught.value is copy.primary
    assert_retired(copy)


@pytest.mark.parametrize("cleanup_at", ["input", "output"])
def test_copy_io_error_keeps_copytree_aggregation(copy, cleanup_at):
    copy.primary = OSError("primary staging read failure")
    copy.cleanup_at = cleanup_at
    copy.cleanup = KeyboardInterrupt("secondary staging close interruption")
    with pytest.raises(shutil.Error, match="primary staging read failure"):
        copy.run()
    assert_retired(copy)


@pytest.mark.parametrize("cleanup_at", ["input", "output"])
@pytest.mark.parametrize("cleanup", [OSError, KeyboardInterrupt])
def test_fresh_close_failure_keeps_existing_policy(copy, cleanup_at, cleanup):
    copy.cleanup_at = cleanup_at
    copy.cleanup = cleanup("fresh staging stream close failure")
    expected = shutil.Error if cleanup is OSError else cleanup
    with pytest.raises(expected, match="fresh staging stream close failure"):
        copy.run()
    assert_retired(copy)


def test_healthy_copy_keeps_bytes_and_retires_both_streams(copy):
    copy.run()
    assert (copy.destination / "input").read_bytes() == copy.payload
    assert copy.writes == [copy.payload]
    assert_retired(copy)

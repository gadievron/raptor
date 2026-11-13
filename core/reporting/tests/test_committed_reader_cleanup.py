"""Committed report reads retain their primary failure through stream cleanup."""
import errno
import os
from types import SimpleNamespace

import pytest

from core.reporting import writer
from core.reporting.builders import build_document
from core.reporting.document import ReportContext
from core.reporting.options import ReportOptions


@pytest.fixture
def captured_reader(tmp_path, monkeypatch):
    output = tmp_path / "report"
    context = ReportContext("scan", "saved", state="completed")
    publication = writer.publish_report(context, build_document(context), output,
                                        options=ReportOptions(formats=("json",)))
    target = output / ".reporting" / publication.generation / "manifest.json"
    before = {p: p.read_bytes() for p in output.rglob("*") if p.is_file()}
    state = SimpleNamespace(output=output, context=context, target=target, before=before,
                            primary=None, cleanup=None, streams=[])
    original = writer.open_regular_beneath

    class OwnedStream:
        def __init__(self, stream):
            self.stream = stream
            self.fd = stream.fileno()
            self.reads = []
            self.exits = 0

        def __enter__(self):
            return self

        def fileno(self):
            return self.stream.fileno()

        def read(self, limit):
            data = self.stream.read(limit)
            self.reads.append(data)
            if state.primary is not None:
                raise state.primary
            return data

        def __exit__(self, *args):
            self.exits += 1
            self.stream.close()
            if state.cleanup is not None:
                raise state.cleanup
            return False

    def open_captured(root, relative, **kwargs):
        stream = original(root, relative, **kwargs)
        if relative != target.relative_to(output):
            return stream
        assert root == output and kwargs == {"mode": "rb"}
        assert stream is not None
        owned = OwnedStream(stream)
        state.streams.append(owned)
        return owned

    monkeypatch.setattr(writer, "open_regular_beneath", open_captured)
    try:
        yield state
    finally:
        for owned in state.streams:
            if not owned.stream.closed:
                owned.stream.close()


def _assert_consumed(state, *, read=True):
    assert len(state.streams) == 1
    owned = state.streams[0]
    assert owned.exits == 1 and owned.stream.closed
    with pytest.raises(OSError) as raised:
        os.fstat(owned.fd)
    assert raised.value.errno == errno.EBADF
    assert owned.reads == ([state.before[state.target]] if read else [])
    assert all(path.read_bytes() == data for path, data in state.before.items())


@pytest.mark.parametrize("error_type", [KeyboardInterrupt, SystemExit, RuntimeError])
def test_committed_loader_preserves_read_failure_after_consuming_close_error(captured_reader, error_type):
    state = captured_reader
    primary = error_type("read interrupted")
    state.primary = primary
    state.cleanup = OSError(errno.EIO, "consumed close failed")
    with pytest.raises(error_type) as raised:
        writer.load_committed_report(state.output, root=state.output)
    assert raised.value is primary
    _assert_consumed(state)


def test_committed_loader_healthy_read_closes_stream(captured_reader):
    state = captured_reader
    context, document, _ = writer.load_committed_report(state.output, root=state.output)
    assert context.snapshot_id == document.snapshot_id == state.context.snapshot_id
    _assert_consumed(state)


def test_committed_loader_fresh_close_error_remains_visible(captured_reader):
    state = captured_reader
    state.cleanup = OSError(errno.EIO, "fresh consumed close failed")
    with pytest.raises(ValueError, match="manifest unavailable") as raised:
        writer.load_committed_report(state.output, root=state.output)
    assert raised.value.__cause__ is state.cleanup
    _assert_consumed(state)


def test_committed_reader_size_refusal_survives_close_error(captured_reader):
    state = captured_reader
    state.cleanup = OSError(errno.EIO, "consumed close failed")
    with pytest.raises(ValueError, match="exceeds read limit"):
        writer._read_bytes(state.target, limit=1, root=state.output)
    _assert_consumed(state, read=False)

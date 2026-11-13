"""Saved outcomes projection must preserve cancellation across read cleanup."""
import errno
import json
import os
from types import SimpleNamespace

import pytest

from core.source import beneath
from packages.exploitability_validation.report import write_validation_outcomes


@pytest.fixture
def artifact_reader(tmp_path, monkeypatch):
    root = tmp_path / "run"
    root.mkdir()
    source = root / "findings.json"
    source.write_text(json.dumps({"findings": [{"id": "F1", "file": "a.c", "line": 1,
                                               "final_status": "inconclusive"}]}))
    state = SimpleNamespace(root=root, source=source, before=source.read_bytes(),
                            primary=None, cleanup=None, streams=[])
    original = beneath.open_regular_beneath

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

    def open_captured(owner, relative, **kwargs):
        stream = original(owner, relative, **kwargs)
        if stream is None:
            return None
        assert owner == root and relative == source.relative_to(root) and kwargs == {"mode": "rb"}
        owned = OwnedStream(stream)
        state.streams.append(owned)
        return owned

    monkeypatch.setattr(beneath, "open_regular_beneath", open_captured)
    try:
        yield state
    finally:
        for owned in state.streams:
            if not owned.stream.closed:
                owned.stream.close()


def _assert_consumed(state):
    assert len(state.streams) == 1
    owned = state.streams[0]
    assert owned.exits == 1 and owned.stream.closed
    with pytest.raises(OSError) as raised:
        os.fstat(owned.fd)
    assert raised.value.errno == errno.EBADF
    assert owned.reads == [state.before]
    assert state.source.read_bytes() == state.before


@pytest.mark.parametrize("error_type", [KeyboardInterrupt, SystemExit])
def test_saved_outcomes_export_preserves_cancel_after_close_error(artifact_reader, error_type):
    state = artifact_reader
    primary = error_type("read interrupted")
    state.primary = primary
    state.cleanup = OSError(errno.EIO, "consumed close failed")
    with pytest.raises(error_type) as raised:
        write_validation_outcomes(state.root)
    assert raised.value is primary
    _assert_consumed(state)
    assert not (state.root / "validation-outcomes.json").exists()


def test_saved_outcomes_healthy_read_preserves_recorded_status(artifact_reader):
    state = artifact_reader
    output = write_validation_outcomes(state.root)
    _assert_consumed(state)
    assert json.loads(output.read_text()) == [{"finding_id": "F1", "status": "inconclusive", "file": "a.c", "line": 1}]


def test_saved_outcomes_fresh_close_error_keeps_refusal_fallback(artifact_reader, caplog):
    state = artifact_reader
    state.cleanup = OSError(errno.EIO, "fresh consumed close failed")
    assert write_validation_outcomes(state.root) is None
    _assert_consumed(state)
    assert "Reporting artifact refused (OSError)" in caplog.text
    assert not (state.root / "validation-outcomes.json").exists()


def test_saved_outcomes_body_refusal_keeps_primary_error_kind(artifact_reader, caplog):
    state = artifact_reader
    state.primary = ValueError("read refused")
    state.cleanup = OSError(errno.EIO, "consumed close failed")
    assert write_validation_outcomes(state.root) is None
    _assert_consumed(state)
    assert "Reporting artifact refused (ValueError)" in caplog.text
    assert not (state.root / "validation-outcomes.json").exists()


def test_saved_outcomes_symlink_refusal_stays_confined(artifact_reader):
    state = artifact_reader
    private = state.root.parent / "private.json"
    state.source.rename(private)
    state.source.symlink_to(private)
    assert write_validation_outcomes(state.root) is None
    assert state.streams == []
    assert private.read_bytes() == state.before and state.source.is_symlink()
    assert not (state.root / "validation-outcomes.json").exists()

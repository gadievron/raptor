"""Finalisation failures retain distinct evidence snapshots for recovery."""

import errno
import json
import logging
import os

import pytest

from core.sandbox import evidence, summary


@pytest.fixture(autouse=True)
def isolated_state(tmp_path):
    from core.testing.sandbox_state_scope import isolated_sandbox_state
    from core.testing.state_isolation import pin_user_state_dirs
    with isolated_sandbox_state(()):
        with pytest.MonkeyPatch.context() as patch:
            patch.setenv('XDG_DATA_HOME', str(tmp_path / 'xdg'))
            pin_user_state_dirs(patch, tmp_path)
            yield


@pytest.fixture
def monkeypatch(isolated_state):
    """Undo body patches before restoring fixture-owned state."""
    with pytest.MonkeyPatch.context() as patch:
        yield patch


@pytest.mark.parametrize("stage", ["open", "stat", "read", "write"])
@pytest.mark.parametrize("legacy", [False, True])
def test_failures_retain_evidence_without_overwriting_earlier_attempts(
    tmp_path, monkeypatch, caplog, stage, legacy,
):
    source = (tmp_path / summary.DENIALS_FILE if legacy else
              evidence.evidence_write_path(tmp_path, summary.DENIALS_FILE))
    source.parent.mkdir(parents=True, exist_ok=True)
    first = b'{"type":"network","cmd":"first"}\n'
    second = b'{"type":"network","cmd":"second"}\n'
    source.write_bytes(first)
    previous_summary = tmp_path / summary.SUMMARY_FILE
    previous_summary.write_bytes(b'{"previous":"summary"}\n')
    real_open, real_fstat, real_read = os.open, os.fstat, os.read
    tracked = set()

    def failing_open(path, *args, **kwargs):
        claimed = ".summarising." in str(path)
        if claimed and stage == "open":
            raise OSError(errno.EIO, "injected open failure")
        fd = real_open(path, *args, **kwargs)
        if claimed:
            tracked.add(fd)
        else:
            tracked.discard(fd)
        return fd

    def failing_fstat(fd):
        if fd in tracked and stage == "stat":
            raise OSError(errno.EIO, "injected stat failure")
        return real_fstat(fd)

    def failing_read(fd, size):
        if fd in tracked and stage == "read":
            raise OSError(errno.EIO, "injected read failure")
        return real_read(fd, size)

    def failing_write(*args, **kwargs):
        raise OSError(errno.ENOSPC, "injected summary write failure")

    with monkeypatch.context() as patch:
        patch.setattr(os, "open", failing_open)
        patch.setattr(os, "fstat", failing_fstat)
        patch.setattr(os, "read", failing_read)
        if stage == "write":
            patch.setattr(summary, "write_text_atomically", failing_write)
        with caplog.at_level(logging.WARNING, logger=summary.__name__):
            assert summary.summarize_and_write(tmp_path) is None
            source.write_bytes(second)
            assert summary.summarize_and_write(tmp_path) is None

    snapshots = list(source.parent.glob(source.name + ".summarising.*"))
    assert len(snapshots) == 2
    assert {path.read_bytes() for path in snapshots} == {first, second}
    assert previous_summary.read_bytes() == b'{"previous":"summary"}\n'
    assert not source.exists()
    for path in snapshots:
        assert str(path) in caplog.text
    assert "evidence retained at" in caplog.text


@pytest.mark.parametrize("content,expected", [
    ('{"type":"network","cmd":"valid"}\n', 1),
    ('invalid json\n', 0),
    ('', None),
])
def test_completed_finalization_removes_claimed_stream(tmp_path, content, expected):
    source = tmp_path / summary.DENIALS_FILE
    source.write_text(content, encoding="utf-8")
    result = summary.summarize_and_write(tmp_path)
    if expected is None:
        assert result is None
    else:
        assert result["total_denials"] == expected
        persisted = json.loads((tmp_path / summary.SUMMARY_FILE).read_text())
        assert persisted["total_denials"] == expected
        if not expected:
            assert persisted["corrupt_lines"] == 1
    assert not source.exists()
    assert not list(tmp_path.glob(source.name + ".summarising.*"))

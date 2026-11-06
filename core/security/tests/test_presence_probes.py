"""Metadata failures retain inputs for the caller's refusal/reporting path."""
import errno
import os
from types import ModuleType

import pytest

from core.security import capped_read
from core.sandbox import evidence, summary, triage
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture(autouse=True)
def owned_user_state(tmp_path):
    with pytest.MonkeyPatch.context() as monkeypatch:
        pin_user_state_dirs(monkeypatch, tmp_path / 'state')
        monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'xdg'))
        yield


@pytest.fixture
def monkeypatch(owned_user_state):
    """Undo body patches before restoring the file-owned state."""
    with pytest.MonkeyPatch.context() as patch:
        yield patch


def probe_os(monkeypatch, error, *paths):
    """Replace consumer bindings; leave the shared os module unchanged."""
    original = os.lstat
    selected = {os.fspath(path) for path in paths}
    local_os = ModuleType('presence_probe_os')
    vars(local_os).update(vars(os))

    def lstat(path, *args, **kwargs):
        if os.fspath(path) in selected:
            raise OSError(error, 'metadata unavailable')
        return original(path, *args, **kwargs)

    local_os.lstat = lstat
    monkeypatch.setattr(capped_read, 'os', local_os)
    monkeypatch.setattr(triage, 'os', local_os)


@pytest.mark.parametrize('error,expected', [
    pytest.param(errno.ENOENT, False, id='missing'),
    pytest.param(errno.ENOTDIR, False, id='not-directory'),
    pytest.param(errno.EACCES, True, id='permission-denied'),
    pytest.param(errno.EIO, True, id='io-error'),
])
def test_only_definite_absence_returns_false(tmp_path, monkeypatch, error, expected):
    path = tmp_path / 'artifact'
    probe_os(monkeypatch, error, path)
    assert capped_read.path_may_exist(path) is expected


def test_dangling_link_remains_present(tmp_path):
    link = tmp_path / 'link'
    link.symlink_to(tmp_path / 'missing')
    assert capped_read.path_may_exist(link)


@pytest.mark.parametrize('error', [
    pytest.param(errno.EACCES, id='permission-denied'),
    pytest.param(errno.EIO, id='io-error'),
])
def test_unreadable_metadata_still_produces_triage_report(tmp_path, monkeypatch, error):
    path = tmp_path / summary.SUMMARY_FILE
    path.write_text('{}')
    probe_os(monkeypatch, error, path)
    original_read = triage.read_capped

    def unavailable_summary(current, limit):
        return None if current == path else original_read(current, limit)

    monkeypatch.setattr(triage, 'read_capped', unavailable_summary)
    report = triage.triage_run(tmp_path, allow_legacy=False)
    assert report is not None
    assert report['inputs']['integrity']['sandbox_summary'] == triage._INTEGRITY_TAMPERED


def test_unknown_canonical_presence_does_not_select_legacy(tmp_path, monkeypatch):
    new = evidence.evidence_write_path(tmp_path, summary.DENIALS_FILE)
    old = evidence.legacy_read_path(tmp_path, summary.DENIALS_FILE)
    old.write_text('{"type":"network","cmd":"older evidence"}\n')
    probe_os(monkeypatch, errno.EACCES, new)
    assert evidence.resolve_read_path(tmp_path, summary.DENIALS_FILE) == new
    assert old.read_text().startswith('{"type":"network"')


def test_truly_absent_artifacts_still_produce_no_report(tmp_path):
    assert triage.triage_run(tmp_path, allow_legacy=False) is None

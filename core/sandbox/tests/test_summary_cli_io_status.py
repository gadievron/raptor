"""Explicit summary commands report storage failures without losing evidence."""

import errno
import json
import os
from pathlib import Path
from types import ModuleType

import pytest

from core.sandbox import evidence, summary
from core.testing.sandbox_state_scope import isolated_sandbox_state
from core.testing.state_isolation import pin_user_state_dirs


CONTROL = 'owned-\x1b[31m\r\n\x85\u202e'
PAYLOAD = b'{"type":"write","path":"/owned/evidence"}\n'


@pytest.fixture(autouse=True)
def owned_state(tmp_path):
    with isolated_sandbox_state(()), pytest.MonkeyPatch.context() as patch:
        pin_user_state_dirs(patch, tmp_path / 'state')
        patch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
        yield


@pytest.fixture
def monkeypatch(owned_state):
    with pytest.MonkeyPatch.context() as patch:
        yield patch


def seed(run, location, payload=PAYLOAD):
    run.mkdir(parents=True, exist_ok=True)
    source = (evidence.evidence_write_path(run, summary.DENIALS_FILE)
              if location == 'canonical' else run / summary.DENIALS_FILE)
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes(payload)
    return source


def install_fault(monkeypatch, run, source, stage, request):
    private = ModuleType('summary_status_os')
    vars(private).update(vars(os))
    monkeypatch.setattr(summary, 'os', private)
    error = OSError(errno.EIO, CONTROL, str(source))
    claimed_fds, opened, closed = set(), [], []
    owned_fds = set()

    def release_if_needed(fd):
        if fd in owned_fds:
            os.close(fd)
            owned_fds.remove(fd)

    def replace(src, dst):
        if Path(src) == source and stage == 'rename':
            raise error
        return os.replace(src, dst)

    def open_fd(path, *args, **kwargs):
        claimed = str(path).startswith(str(source) + '.summarising.')
        if claimed and stage == 'open':
            raise error
        fd = os.open(path, *args, **kwargs)
        request.addfinalizer(lambda: release_if_needed(fd))
        owned_fds.add(fd)
        if claimed:
            claimed_fds.add(fd)
            opened.append(fd)
        return fd

    def fstat(fd):
        if fd in claimed_fds and stage == 'stat':
            raise error
        return os.fstat(fd)

    def read(fd, count):
        if fd in claimed_fds and stage == 'read':
            raise error
        return os.read(fd, count)

    def close(fd):
        os.close(fd)
        owned_fds.discard(fd)
        if fd in claimed_fds:
            claimed_fds.remove(fd)
            closed.append(fd)

    private.replace, private.open = replace, open_fd
    private.fstat, private.read, private.close = fstat, read, close
    output = run / summary.SUMMARY_FILE
    if stage == 'write':
        # A real destination collision exercises the atomic writer.
        output.mkdir()
        (output / 'owned-sentinel').write_bytes(b'preserve')
    else:
        output.write_bytes(b'{"previous":"summary"}\n')
    return opened, closed


def assert_retained(run, source, stage, opened, closed):
    assert opened == closed
    snapshots = list(source.parent.glob(source.name + '.summarising.*'))
    if stage == 'rename':
        assert source.read_bytes() == PAYLOAD
        assert not snapshots
    else:
        assert not source.exists()
        assert len(snapshots) == 1
        assert snapshots[0].read_bytes() == PAYLOAD
    output = run / summary.SUMMARY_FILE
    if stage == 'write':
        assert (output / 'owned-sentinel').read_bytes() == b'preserve'
    else:
        assert output.read_bytes() == b'{"previous":"summary"}\n'


@pytest.mark.parametrize('stage', ['rename', 'open', 'stat', 'read', 'write'])
@pytest.mark.parametrize('location', ['canonical', 'legacy'])
@pytest.mark.parametrize('mode', ['single', 'sweep'])
def test_cli_reports_io_failure_and_sweep_continues(tmp_path, monkeypatch, capsys, caplog, request,
                                                  stage, location, mode):
    project = tmp_path / 'project'
    run = project / ('1-' + CONTROL)
    source = seed(run, location)
    opened, closed = install_fault(monkeypatch, run, source, stage, request)
    if mode == 'sweep':
        before, after = project / '0-before', project / '2-after'
        seed(before, location)
        seed(after, location)
        args = ['--sweep', str(project)]
    else:
        args = [str(run)]
    code = summary._cli_main(args)
    assert_retained(run, source, stage, opened, closed)
    captured = capsys.readouterr()
    if mode == 'sweep':
        for healthy in (before, after):
            result = json.loads((healthy / summary.SUMMARY_FILE).read_text())
            assert result['total_denials'] == 1
        assert '2 summary file(s) written' in captured.out
        assert '2 total denials' in captured.out
    assert code == 1
    assert 'error: cannot finalize' in captured.err
    assert 'no denials recorded' not in captured.out
    if stage != 'rename':
        assert 'evidence retained at' in caplog.text
    assert all(c.isprintable() or c == '\n' for c in captured.err)
    assert len(captured.err) < 1200


@pytest.mark.parametrize('stage', ['rename', 'open', 'stat', 'read', 'write'])
@pytest.mark.parametrize('location', ['canonical', 'legacy'])
def test_library_default_remains_best_effort(tmp_path, monkeypatch, request, stage, location):
    run = tmp_path / 'run'
    source = seed(run, location)
    opened, closed = install_fault(monkeypatch, run, source, stage, request)
    assert summary.summarize_and_write(run) is None
    assert_retained(run, source, stage, opened, closed)


@pytest.mark.parametrize('mode', ['single', 'sweep'])
@pytest.mark.parametrize('location', ['canonical', 'legacy'])
@pytest.mark.parametrize('content', ['healthy', 'empty', 'malformed'])
def test_success_empty_and_corrupt_evidence_keep_success_status(tmp_path, capsys,
                                                               mode, location, content):
    project = tmp_path / 'project'
    run = project / 'run'
    payload = {'healthy': PAYLOAD, 'empty': b'', 'malformed': b'invalid json\n'}[content]
    source = seed(run, location, payload)
    args = ['--sweep', str(project)] if mode == 'sweep' else [str(run)]
    assert summary._cli_main(args) == 0
    assert not source.exists()
    assert not list(source.parent.glob(source.name + '.summarising.*'))
    if content == 'empty':
        assert not (run / summary.SUMMARY_FILE).exists()
    else:
        result = json.loads((run / summary.SUMMARY_FILE).read_text())
        assert result['total_denials'] == (content == 'healthy')
        assert result.get('corrupt_lines', 0) == (content == 'malformed')
    assert capsys.readouterr().err == ''


def test_help_documents_failure_status_and_examples(capsys):
    assert summary._cli_main(['--help']) == 0
    output = capsys.readouterr().out
    assert 'Examples:' in output
    assert 'raptor-sandbox-summary /path/to/run' in output
    assert 'raptor-sandbox-summary --sweep /path/to/project' in output
    assert '1 if any finalization fails' in output


@pytest.mark.parametrize('location', ['canonical', 'legacy'])
def test_sweep_inspection_failure_is_not_silently_skipped(tmp_path, monkeypatch, capsys, location):
    project = tmp_path / 'project'
    failed = project / ('1-' + CONTROL)
    source = seed(failed, location)
    healthy = project / '2-healthy'
    seed(healthy, location)
    private = ModuleType('summary_discovery_evidence')
    vars(private).update(vars(evidence))

    def fail_discovery(run, name):
        if run == failed:
            raise OSError(errno.EIO, CONTROL, str(run))
        return evidence.resolve_read_path(run, name)

    private.resolve_read_path = fail_discovery
    monkeypatch.setattr(summary, '_evidence', private)
    code = summary._cli_main(['--sweep', str(project)])
    assert source.read_bytes() == PAYLOAD
    assert not list(source.parent.glob(source.name + '.summarising.*'))
    assert json.loads((healthy / summary.SUMMARY_FILE).read_text())['total_denials'] == 1
    captured = capsys.readouterr()
    assert code == 1
    assert 'error: cannot inspect' in captured.err
    assert '1 summary file(s) written' in captured.out
    assert all(c.isprintable() or c == '\n' for c in captured.err)


@pytest.mark.parametrize('mode', ['single', 'sweep'])
@pytest.mark.parametrize('error_type', [KeyboardInterrupt, SystemExit], ids=['interrupt', 'exit'])
def test_cli_preserves_cancellation(tmp_path, monkeypatch, request, mode, error_type):
    project = tmp_path / 'project'
    run = project / 'run'
    source = seed(run, 'canonical')
    opened, closed = install_fault(monkeypatch, run, source, 'read', request)
    error = error_type('owned cancellation')

    def cancel(fd, count):
        raise error

    monkeypatch.setattr(summary.os, 'read', cancel)
    args = ['--sweep', str(project)] if mode == 'sweep' else [str(run)]
    with pytest.raises(error_type) as caught:
        summary._cli_main(args)
    assert caught.value is error
    assert_retained(run, source, 'read', opened, closed)


def test_single_run_pending_loss_write_failure_is_an_error(tmp_path, capsys):
    run = tmp_path / CONTROL
    run.mkdir()
    output = run / summary.SUMMARY_FILE
    output.mkdir()
    (output / 'owned-sentinel').write_bytes(b'preserve')
    summary._record_evidence_write_failure(run)
    code = summary._cli_main([str(run)])
    assert summary.get_evidence_write_failure(run) is True
    assert (output / 'owned-sentinel').read_bytes() == b'preserve'
    assert not (run / summary.DENIALS_FILE).exists()
    captured = capsys.readouterr()
    assert code == 1
    assert 'error: cannot finalize' in captured.err
    assert 'no denials recorded' not in captured.out

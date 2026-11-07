"""Host-output cleanup diagnostics escape metadata and retain retry ownership."""
import threading

import pytest

from core.sandbox import host
from core.security.log_sanitisation import has_nonprintable, sanitise_for_terminal


@pytest.mark.parametrize('payload', [
    pytest.param('\nforged warning', id='newline'),
    pytest.param('\x1b[2J', id='escape'),
    pytest.param('\u202ealtered', id='bidi'),
    pytest.param('\udc80', id='surrogate'),
    pytest.param('x' * 5000, id='long'),
])
@pytest.mark.parametrize('failure', ['refused', 'os-error', 'other-error'])
def test_cleanup_warning_bounds_and_escapes_metadata(tmp_path, monkeypatch, caplog, payload, failure):
    path = str(tmp_path / ('owned-' + payload))
    calls = []
    problem = (OSError(5, 'cleanup ' + payload, path) if failure == 'os-error'
               else type('Cleanup' + (payload if payload != '\udc80' else 'Failure'), (RuntimeError,), {})('cleanup ' + payload))

    def remove(value):
        calls.append(value)
        if failure == 'refused':
            return False
        raise problem

    monkeypatch.setattr(host, 'rmtree_hardened', remove)
    assert host._remove_owned_output(path) is False
    assert calls == [path]
    records = [record for record in caplog.records if record.name == host.log.name]
    assert len(records) == 1
    record = records[0]
    message = record.getMessage()
    assert not has_nonprintable(message)
    assert sanitise_for_terminal(path) in message
    assert len(message) < 1400
    assert record.exc_info is None and record.stack_info is None
    if failure != 'refused':
        assert sanitise_for_terminal(type(problem).__name__, max_len=64) in message
        assert sanitise_for_terminal(str(problem)) in message


@pytest.mark.parametrize('failure', ['refused', 'exception'])
@pytest.mark.parametrize('name', [
    pytest.param('owned\noutput', id='newline'),
    pytest.param('owned\x1b[2J', id='escape'),
    pytest.param('owned\u202eoutput', id='bidi'),
])
def test_failed_cleanup_retains_real_output_for_retry(tmp_path, monkeypatch, caplog, failure, name):
    output = tmp_path / name
    output.mkdir()
    marker = output / 'keep'
    marker.write_bytes(b'owned output')
    native_remove = host.rmtree_hardened
    owner = object.__new__(host.SandboxHost)
    owner._daemon_fds_lock = threading.Lock()
    owner._owned_output = str(output)

    def fail(path):
        assert path == str(output)
        if failure == 'exception':
            raise OSError(5, 'cannot remove\n' + str(output))
        return False

    monkeypatch.setattr(host, 'rmtree_hardened', fail)
    owner._cleanup_owned_output()
    assert owner._owned_output == str(output)
    assert marker.read_bytes() == b'owned output'
    assert all(not has_nonprintable(record.getMessage()) for record in caplog.records)
    monkeypatch.setattr(host, 'rmtree_hardened', native_remove)
    owner._cleanup_owned_output()
    assert owner._owned_output is None
    assert not output.exists()


def test_successful_cleanup_is_silent(tmp_path, caplog):
    output = tmp_path / 'owned'
    output.mkdir()
    assert host._remove_owned_output(str(output)) is True
    assert not output.exists()
    assert not caplog.records


@pytest.mark.parametrize('problem', [KeyboardInterrupt('cancel'), SystemExit(17)], ids=['interrupt', 'exit'])
def test_cleanup_preserves_cancellation(tmp_path, monkeypatch, caplog, problem):
    def cancel(path):
        raise problem

    monkeypatch.setattr(host, 'rmtree_hardened', cancel)
    with pytest.raises(type(problem)) as caught:
        host._remove_owned_output(str(tmp_path / 'owned'))
    assert caught.value is problem
    assert not caplog.records

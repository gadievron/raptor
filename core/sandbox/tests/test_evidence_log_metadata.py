"""Evidence failures retain their outcomes while log metadata stays inert."""
import errno
import json
import logging
import os
import stat
from types import ModuleType

import pytest

from core.sandbox import evidence
from core.testing.state_isolation import pin_user_state_dirs


pytestmark = pytest.mark.skipif(os.name != 'posix', reason='requires POSIX control-character filenames')
CONTROL = 'owned-\x1b[31m\r\n\x85\u202e'


@pytest.fixture(autouse=True)
def owned_state(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))


@pytest.fixture(params=['control', 'long'])
def held(tmp_path, monkeypatch, request):
    run = tmp_path / CONTROL
    if request.param == 'long':
        run = run / ('long-' + 'x' * 100) / ('long-' + 'y' * 100)
    run.mkdir(parents=True)
    handle = evidence.EvidenceFile.open(run, 'owned.jsonl')
    request.addfinalizer(lambda: handle.close(verify=False))
    # Faults affect only this consumer, not pytest, logging or other modules.
    local_os = ModuleType('owned_evidence_os')
    vars(local_os).update(vars(os))
    monkeypatch.setattr(evidence, 'os', local_os)
    return handle, local_os


KINDS = ['short-write', 'write-error', 'encoding', 'missing', 'swapped',
         'truncated', 'path-metadata', 'fd-metadata', 'fd-error', 'close-error']


@pytest.mark.parametrize('kind', KINDS)
def test_warning_metadata_is_safe_without_changing_failure_semantics(held, caplog, kind):
    handle, local_os = held
    caplog.set_level(logging.WARNING, logger=evidence.__name__)
    if kind == 'short-write':
        original = local_os.write
        def partial(fd, data):
            return original(fd, data[:2]) if fd == handle.fd else original(fd, data)
        local_os.write = partial
        assert handle.write_line('{"first":true}\n') is False
        local_os.write = original
        assert handle.write_line('{"after":true}\n') is True
        assert handle.path.read_bytes() == b'{"\n{"after":true}\n'
        assert handle.verify() is True
    elif kind == 'write-error':
        original = local_os.write
        def failed(fd, data):
            if fd == handle.fd:
                raise OSError(errno.EIO, CONTROL)
            return original(fd, data)
        local_os.write = failed
        assert handle.write_line('{"owned":true}\n') is False
        assert handle.path.read_bytes() == b''
    elif kind == 'encoding':
        assert handle.write_line('\ud800') is False
        assert handle.path.read_bytes() == b''
    elif kind == 'close-error':
        original = local_os.close
        closed = []
        def failed_close(fd):
            original(fd)
            if fd == handle.fd:
                closed.append(fd)
                raise OSError(errno.EIO, CONTROL)
        local_os.close = failed_close
        assert handle.close(verify=False) is False
        assert handle.close(verify=False) is False
        assert closed == [handle.fd]
        assert handle._fd_released is True
    else:
        if kind == 'missing':
            handle.path.unlink()
        elif kind == 'swapped':
            handle.path.unlink()
            handle.path.write_bytes(b'owned replacement')
        elif kind == 'truncated':
            assert handle.write_line('{"owned":true}\n') is True
            handle.path.write_bytes(b'')
        elif kind == 'path-metadata':
            handle.path.chmod(0o622)
        elif kind == 'fd-metadata':
            original = local_os.fstat
            def unsafe_stat(fd):
                value = original(fd)
                if fd != handle.fd:
                    return value
                fields = list(value)
                fields[stat.ST_MODE] |= 0o022
                return os.stat_result(fields)
            local_os.fstat = unsafe_stat
        elif kind == 'fd-error':
            original = local_os.lseek
            def failed_seek(fd, offset, whence):
                if fd == handle.fd:
                    raise OSError(errno.EIO, CONTROL)
                return original(fd, offset, whence)
            local_os.lseek = failed_seek
        assert handle.verify() is False

    records = [record for record in caplog.records if record.name == evidence.__name__]
    assert len(records) == 1
    text = logging.Formatter('%(message)s').format(records[0])
    assert 'evidence' in text
    assert 'owned-' in text
    assert all(char not in text for char in ('\x1b', '\r', '\n', '\x85', '\u202e'))
    assert len(text) < 1200
    if kind in ('missing', 'swapped', 'truncated', 'path-metadata', 'fd-metadata', 'fd-error'):
        assert 'SANDBOX EVIDENCE TAMPER SUSPECTED' in text
    if kind == 'fd-metadata':
        assert '(descriptor:' in text


def test_valid_records_keep_raw_identity_and_clean_close(held, caplog):
    handle, _ = held
    record = {'owned': True, 'path': CONTROL}
    assert handle.write_record(record) is True
    assert json.loads(handle.path.read_bytes()) == record
    assert CONTROL in handle.path.parts
    assert handle.verify() is True
    assert handle.close() is True
    assert not [r for r in caplog.records if r.name == evidence.__name__]

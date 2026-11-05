"""Reader fault injection must leave shared modules usable by other code."""
import errno
import json
import os

import pytest

from core.sandbox import triage


@pytest.mark.usefixtures('private_triage_readers')
@pytest.mark.parametrize('operation', ['read', 'close', 'decode'])
def test_fault_injection_leaves_unrelated_file_io_usable(tmp_path, monkeypatch, operation):
    path = tmp_path / 'input'
    path.write_bytes(b'{}')
    shared_read, shared_close, shared_loads = os.read, os.close, json.loads

    def fail(*args, **kwargs):
        if operation == 'decode':
            raise ValueError('injected decode failure')
        raise OSError(errno.EIO, 'injected reader failure')

    owner, name = (triage.json, 'loads') if operation == 'decode' else (triage.os, operation)
    monkeypatch.setattr(owner, name, fail)
    assert os.read is shared_read
    assert os.close is shared_close
    assert json.loads is shared_loads

    fd = os.open(path, os.O_RDONLY)
    try:
        assert os.read(fd, 2) == b'{}'
        assert json.loads('{}') == {}
    finally:
        os.close(fd)
    with pytest.raises((OSError, ValueError)):
        getattr(owner, name)(None)

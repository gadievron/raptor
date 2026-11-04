"""Consent minting publishes a nonce only after its full digest is written."""
import errno
import os

import pytest

from core.sandbox import disable_consent as dc


@pytest.mark.parametrize('chunk_size', [1, 7, 32])
def test_partial_writes_produce_valid_complete_digest(tmp_path, monkeypatch, chunk_size):
    real_write = os.write
    calls = []

    def short_write(fd, data):
        calls.append(bytes(data))
        return real_write(fd, data[:chunk_size])

    monkeypatch.setattr(dc.os, 'write', short_write)
    nonce = dc._mint_nonce(tmp_path)
    path = tmp_path / dc._nonce_filename(nonce)
    expected = (dc._nonce_digest(nonce) + '\n').encode()
    assert path.read_bytes() == expected
    assert calls[0] == expected
    assert len(calls) > 1
    assert dc._nonce_file_consents(path, nonce) is True


class Cancelled(BaseException):
    pass


@pytest.mark.parametrize('failure', ['zero', 'oserror', 'cancelled'])
def test_failed_write_does_not_return_nonce_and_closes_descriptor(
        tmp_path, monkeypatch, failure):
    real_write, real_close = os.write, os.close
    calls, closed = [], []
    error = OSError(errno.ENOSPC, 'full') if failure == 'oserror' else Cancelled()

    def interrupted_write(fd, data):
        calls.append(bytes(data))
        if len(calls) == 1:
            return real_write(fd, data[:5])
        if failure == 'zero':
            return 0
        raise error

    def close(fd):
        closed.append(fd)
        real_close(fd)

    with monkeypatch.context() as scoped:
        scoped.setattr(dc.os, 'write', interrupted_write)
        scoped.setattr(dc.os, 'close', close)
        expected_error = Cancelled if failure == 'cancelled' else OSError
        with pytest.raises(expected_error) as caught:
            dc._mint_nonce(tmp_path)
    if failure == 'zero':
        assert caught.value.errno == errno.EIO
    else:
        assert caught.value is error
    assert len(calls) == 2
    assert len(closed) == 1
    files = list(tmp_path.iterdir())
    assert len(files) == 1
    assert files[0].read_bytes() == calls[0][:5]

"""Handled stdin EOF must not hide a fresh close error or cancellation."""

import errno
import io
import os
import signal
from types import SimpleNamespace

import pytest

from core.sandbox import _capture as capture
from core.testing.module_bindings import patch_module_attribute


pytestmark = pytest.mark.skipif(os.name != 'posix', reason='POSIX pipe error contract')


@pytest.mark.parametrize('mode', ['broken-pipe', 'empty', 'ambient'])
@pytest.mark.parametrize('failure_type', [OSError, KeyboardInterrupt], ids=['io', 'cancel'])
def test_stdin_close_failure_remains_visible_after_handled_eof(monkeypatch, mode, failure_type):
    assert signal.getsignal(signal.SIGPIPE) == signal.SIG_IGN
    failure = (OSError(errno.EIO, 'owned stdin close acknowledgement failure')
               if failure_type is OSError else KeyboardInterrupt('owned stdin close cancellation'))
    reader, writer = os.pipe()
    identities = {fd: (os.fstat(fd).st_dev, os.fstat(fd).st_ino) for fd in (reader, writer)}
    writes, closes, broken = [], [], []

    class OwnedInput(io.FileIO):
        def close(self):
            if self.closed:
                return
            super().close()
            closes.append(True)
            raise failure

    stream = None

    def write(fd, data):
        assert fd == writer
        writes.append(bytes(data))
        try:
            return os.write(fd, data)
        except BrokenPipeError as error:
            broken.append(error)
            raise

    def forbid_wait(*args, **kwargs):
        pytest.fail('fresh close failure must surface before process waiting')

    try:
        stream = OwnedInput(writer, 'wb', closefd=True)
        proc = SimpleNamespace(args=['owned-nonexecuting-input'], stdin=stream,
                               stdout=None, stderr=None, text_mode=False,
                               returncode=None, wait=forbid_wait)
        communicator = capture.BoundedCommunicator(1024)
        if mode == 'broken-pipe':
            os.close(reader)
        patch_module_attribute(monkeypatch, capture, 'os', 'write', write)
        communicator.attach(proc)
        payload = b'owned input' if mode == 'broken-pipe' else b''
        if mode == 'ambient':
            try:
                raise ValueError('owned caller exception already being handled')
            except ValueError:
                with pytest.raises(BaseException) as caught:
                    communicator.communicate(input=payload, timeout=1)
        else:
            with pytest.raises(BaseException) as caught:
                communicator.communicate(input=payload, timeout=1)
        assert caught.value is failure
        if mode == 'broken-pipe':
            assert writes == [payload]
            assert len(broken) == 1 and broken[0].errno == errno.EPIPE
        else:
            assert not writes and not broken
        assert closes == [True]
        assert stream.closed and communicator._input_stopped
        assert len(communicator._input) == 0
        with pytest.raises(OSError) as closed:
            os.fstat(writer)
        assert closed.value.errno == errno.EBADF
        assert signal.getsignal(signal.SIGPIPE) == signal.SIG_IGN
    finally:
        if stream is not None and not stream.closed:
            io.FileIO.close(stream)
        for fd, identity in identities.items():
            try:
                info = os.fstat(fd)
            except OSError as error:
                if error.errno != errno.EBADF:
                    raise
                continue
            if (info.st_dev, info.st_ino) == identity:
                os.close(fd)

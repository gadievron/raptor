"""Only a successful empty read can confirm an empty exec-status pipe."""
import errno
import os
import sys

import pytest

from core.sandbox import supervised as sup
from core.testing.module_bindings import patch_module_attribute

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux supervisor pipes')


@pytest.mark.parametrize('prefix', [b'', b'owned failure'], ids=['empty', 'partial'])
def test_status_read_error_cannot_be_exec_confirmation(monkeypatch, prefix):
    reader, writer = os.pipe()
    try:
        os.close(writer)
        chunks = [prefix] if prefix else []
        calls = []

        def read(fd, size):
            assert fd == reader and size == 64
            calls.append(True)
            if chunks:
                return chunks.pop(0)
            raise OSError(errno.EIO, 'owned status read failure')

        patch_module_attribute(monkeypatch, sup, 'os', 'read', read)
        assert sup._read_line_deadline(reader, 1) is None
        assert len(calls) == (2 if prefix else 1)
    finally:
        os.close(reader)


@pytest.mark.parametrize('payload', [b'', b'owned report\n'])
def test_interrupted_status_read_retries_to_real_pipe_result(monkeypatch, payload):
    reader, writer = os.pipe()
    try:
        if payload:
            os.write(writer, payload)
        os.close(writer)
        original = os.read
        calls = []

        def read(fd, size):
            assert fd == reader
            calls.append(True)
            if len(calls) == 1:
                raise InterruptedError(errno.EINTR, 'owned interrupted read')
            return original(fd, size)

        patch_module_attribute(monkeypatch, sup, 'os', 'read', read)
        assert sup._read_line_deadline(reader, 1) == payload.rstrip(b'\n')
        assert len(calls) == 2
    finally:
        os.close(reader)

"""Probe descriptors retire without changing active or fresh cancellation."""

import errno
import os

import pytest

from core.inventory import languages
from core.testing.module_bindings import patch_module_attribute


@pytest.fixture
def probe_case(tmp_path, monkeypatch):
    source = tmp_path / 'owned-script'
    source.write_text('#!/bin/sh\necho fixture\n')
    native_read, native_close = os.read, os.close
    identities, closes = [], []

    def run(read_error=None, close_error=None):
        def read(fd, size):
            info = os.fstat(fd)
            identities.append((fd, info.st_dev, info.st_ino))
            if read_error is not None:
                raise read_error
            return native_read(fd, size)

        def close(fd):
            native_close(fd)
            closes.append(fd)
            if close_error is not None:
                raise close_error

        patch_module_attribute(monkeypatch, languages, 'os', 'read', read)
        patch_module_attribute(monkeypatch, languages, 'os', 'close', close)
        return languages.detect_language_from_shebang(str(source))

    yield run, identities, closes
    for fd, device, inode in identities:
        try:
            info = os.fstat(fd)
        except OSError:
            continue
        if (info.st_dev, info.st_ino) == (device, inode):
            native_close(fd)


def _assert_retired(identities, closes):
    assert len(identities) == 1
    fd, device, inode = identities[0]
    assert closes == [fd]
    try:
        info = os.fstat(fd)
    except OSError as error:
        assert error.errno == errno.EBADF
    else:
        assert (info.st_dev, info.st_ino) != (device, inode)


@pytest.mark.parametrize('failure', [KeyboardInterrupt, SystemExit, RuntimeError])
def test_active_read_error_survives_secondary_close_error(probe_case, failure):
    run, identities, closes = probe_case
    primary = failure('primary read failure')
    with pytest.raises(failure) as caught:
        run(primary, OSError('secondary close failure'))
    assert caught.value is primary
    _assert_retired(identities, closes)


def test_close_only_failure_is_still_reported(probe_case):
    run, identities, closes = probe_case
    primary = OSError('close failure')
    with pytest.raises(OSError) as caught:
        run(close_error=primary)
    assert caught.value is primary
    _assert_retired(identities, closes)


def test_handled_read_error_keeps_no_language_result(probe_case):
    run, identities, closes = probe_case
    assert run(OSError('read unavailable')) is None
    _assert_retired(identities, closes)


@pytest.mark.parametrize('failure', [KeyboardInterrupt, SystemExit])
def test_fresh_close_cancellation_after_handled_read_error(probe_case, failure):
    run, identities, closes = probe_case
    primary = failure('cancelled after read refusal')
    with pytest.raises(failure) as caught:
        run(OSError('read unavailable'), primary)
    assert caught.value is primary
    _assert_retired(identities, closes)

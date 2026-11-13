"""Best-effort setup tracing must not wait for a diagnostic pipe reader."""
import errno
import os

import pytest

from core.sandbox import mount_ns
from core.testing.module_views import module_function_view

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='owned POSIX FIFO')


def test_phase_trace_refuses_blocking_fifo_open(tmp_path):
    fifo = tmp_path / 'phase.fifo'
    os.mkfifo(fifo)
    calls, failures = [], []

    def guarded_open(path, flags, mode=0o777):
        assert path == str(fifo)
        calls.append(flags)
        # Never perform the pre-fix blocking syscall: there is no reader.
        assert flags & os.O_NONBLOCK, 'phase trace can block opening an unread FIFO'
        try:
            return os.open(path, flags, mode)
        except OSError as exc:
            failures.append(exc.errno)
            raise

    private = module_function_view(mount_ns, bindings={
        'os': module_function_view(os, bindings={
            'environ': {mount_ns._PHASE_TRACE_ENV: str(fifo)}, 'open': guarded_open,
        }),
    })
    private._phase_trace(b'owned marker')
    assert len(calls) == 1
    assert failures == [errno.ENXIO]


def test_phase_trace_still_appends_regular_file(tmp_path):
    path = tmp_path / 'phase.log'
    private = module_function_view(mount_ns, bindings={
        'os': module_function_view(os, bindings={
            'environ': {mount_ns._PHASE_TRACE_ENV: str(path)},
        }),
    })
    private._phase_trace(b'first')
    private._phase_trace(b'second')
    lines = path.read_bytes().splitlines()
    assert len(lines) == 2
    assert lines[0].endswith(b': first') and lines[1].endswith(b': second')


def test_phase_trace_keeps_symlink_refusal(tmp_path):
    target = tmp_path / 'target'
    target.write_bytes(b'untouched')
    link = tmp_path / 'phase.log'
    link.symlink_to(target)
    private = module_function_view(mount_ns, bindings={
        'os': module_function_view(os, bindings={
            'environ': {mount_ns._PHASE_TRACE_ENV: str(link)},
        }),
    })
    private._phase_trace(b'must not follow')
    assert target.read_bytes() == b'untouched'


def test_phase_trace_skips_saturated_fifo_write(tmp_path):
    from contextlib import ExitStack

    fifo = tmp_path / 'full.fifo'
    os.mkfifo(fifo)
    errors = []
    with ExitStack() as owner:
        reader = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
        owner.callback(os.close, reader)
        writer = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
        owner.callback(os.close, writer)
        for _ in range(1024):
            try:
                os.write(writer, b'x' * 65536)
            except BlockingIOError:
                break
        else:
            pytest.fail('owned FIFO did not saturate within bounded writes')

        def guarded_open(path, flags, mode=0o777):
            assert flags & os.O_NONBLOCK, 'phase trace must not block writing a full FIFO'
            return os.open(path, flags, mode)

        def write(fd, data):
            try:
                return os.write(fd, data)
            except OSError as exc:
                errors.append(exc.errno)
                raise

        private = module_function_view(mount_ns, bindings={
            'os': module_function_view(os, bindings={
                'environ': {mount_ns._PHASE_TRACE_ENV: str(fifo)},
                'open': guarded_open, 'write': write,
            }),
        })
        private._phase_trace(b'best effort')
    assert errors == [errno.EAGAIN]

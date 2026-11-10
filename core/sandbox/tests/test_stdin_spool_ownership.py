"""Native input delivery with parent file ownership independent of tracebacks."""

import builtins
from contextlib import contextmanager
import subprocess
import sys
import tempfile

import pytest

from core.sandbox import context
from core.sandbox.tests.capability import requires_landlock, requires_mount, requires_userns
from core.testing.module_views import module_function_view

pytestmark = [
    pytest.mark.slow,
    pytest.mark.linux_native,
    pytest.mark.skipif(sys.platform != 'linux', reason='Linux read-only stdin spool'),
    requires_landlock, requires_mount, requires_userns,
]


@pytest.fixture
def spool_run(tmp_path):
    target, output = tmp_path / 'target', tmp_path / 'output'
    target.mkdir()
    output.mkdir()
    files = []

    def observe_open(path, mode='r', *args, **kwargs):
        result = builtins.open(path, mode, *args, **kwargs)
        if str(path).startswith('/proc/self/fd/') and mode == 'rb':
            assert not result.writable()
            files.append(result)
        return result

    private = module_function_view(context, bindings={
        'sandbox': context.sandbox.__wrapped__, 'open': observe_open,
    })
    try:
        with contextmanager(private.sandbox)(profile='strict', target=str(target), output=str(output)) as run:
            yield run, files
    finally:
        for owned in files:
            if not owned.closed:
                owned.close()


@pytest.mark.parametrize('payload,text', [
    (b'owned\x00witness', False), ('owned \u03bb witness', True), (b'', False),
], ids=['binary', 'unicode-text', 'empty'])
def test_success_retires_spool_after_delivering_complete_input(spool_run, payload, text):
    run, files = spool_run
    result = run(['/bin/cat'], input=payload, text=text, capture_output=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert result.stdout == payload
    assert result.sandbox_info['mount_ns_active'] is True
    assert len(files) == 1 and files[0].closed


def test_failed_command_retires_spool_with_retained_traceback(spool_run):
    run, files = spool_run
    with pytest.raises(subprocess.CalledProcessError) as caught:
        run(['/bin/false'], input=b'owned witness', check=True, capture_output=True, timeout=15)
    assert caught.value.returncode == 1
    assert caught.value.__traceback__ is not None
    assert len(files) == 1 and files[0].closed


def test_timeout_retires_spool_with_retained_traceback(spool_run):
    run, files = spool_run
    with pytest.raises(subprocess.TimeoutExpired) as caught:
        run(['/bin/sh', '-c', 'printf started; sleep 10'], input=b'owned witness',
            capture_output=True, timeout=2)
    assert b'started' in caught.value.output
    assert caught.value.__traceback__ is not None
    assert len(files) == 1 and files[0].closed


@pytest.mark.parametrize('stage', ['write', 'flush', 'readonly-open'])
def test_preparation_failure_retires_acquired_writer(tmp_path, stage):
    target, output = tmp_path / 'target', tmp_path / 'output'
    target.mkdir()
    output.mkdir()
    files = []
    failure = OSError('owned spool preparation refusal')

    class Writer:
        def __init__(self):
            self.file = tempfile.TemporaryFile()
            files.append(self.file)

        def __getattr__(self, name):
            return getattr(self.file, name)

        def write(self, data):
            result = self.file.write(data)
            if stage == 'write':
                raise failure
            return result

        def flush(self):
            self.file.flush()
            if stage == 'flush':
                raise failure

    def imports(name, globals=None, locals=None, fromlist=(), level=0):
        if name == 'tempfile' and level == 0:
            return module_function_view(tempfile, bindings={'TemporaryFile': Writer})
        return builtins.__import__(name, globals, locals, fromlist, level)

    def refuse_open(path, mode='r', *args, **kwargs):
        if str(path).startswith('/proc/self/fd/') and mode == 'rb':
            raise failure
        return builtins.open(path, mode, *args, **kwargs)

    private = module_function_view(context, bindings={
        'sandbox': context.sandbox.__wrapped__, 'open': refuse_open,
    }, import_hook=imports)
    try:
        with contextmanager(private.sandbox)(profile='strict', target=str(target), output=str(output)) as run:
            with pytest.raises(OSError) as caught:
                run(['/bin/false'], input=b'owned witness', capture_output=True, timeout=15)
            assert caught.value is failure
            assert caught.value.__traceback__ is not None
            assert len(files) == 1 and files[0].closed
    finally:
        for owned in files:
            if not owned.closed:
                owned.close()

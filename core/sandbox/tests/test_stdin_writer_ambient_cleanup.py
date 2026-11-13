"""Writer cleanup failures must refuse dispatch after successful preparation."""
import builtins
import subprocess
import sys
import tempfile

import pytest

from core.sandbox import context
from core.sandbox.tests.test_context_decision_pins import _Driver
from core.testing.module_bindings import patch_module_attribute
from core.testing.state_isolation import pin_user_state_dirs

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux input spooling')


@pytest.mark.parametrize('preparation_fails', [False, True], ids=['success', 'write-failure'])
def test_writer_close_failure_cannot_be_hidden_before_dispatch(monkeypatch, tmp_path, preparation_fails):
    cleanup = OSError('owned input writer close failure')
    primary = ValueError('owned input preparation failure')
    factory = tempfile.TemporaryFile
    writers, readers, calls = [], [], []

    class Writer:
        def __init__(self):
            self.stream = factory()
            writers.append(self.stream)

        def __getattr__(self, name):
            return getattr(self.stream, name)

        def write(self, data):
            count = self.stream.write(data)
            if preparation_fails:
                raise primary
            return count

        def close(self):
            self.stream.close()
            raise cleanup

    def open_spool(path, *args, **kwargs):
        stream = builtins.open(path, *args, **kwargs)
        if str(path).startswith('/proc/self/fd/') and args == ('rb',):
            readers.append(stream)
        return stream

    def backend(cmd, **kwargs):
        calls.append(True)
        assert kwargs['stdin'].read() == b'owned input'
        result = subprocess.CompletedProcess(cmd, 0, None, None)
        result._setup_status = None
        return result

    def forbid_process(*args, **kwargs):
        pytest.fail('writer cleanup test must not launch a process')

    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    _Driver(monkeypatch, backend)
    monkeypatch.setattr(context, 'open', open_spool, raising=False)
    monkeypatch.setattr(tempfile, 'TemporaryFile', Writer)
    monkeypatch.setattr(context, '_run_teardown_first_timeout', forbid_process)
    patch_module_attribute(monkeypatch, context, 'subprocess', 'Popen', forbid_process)
    with context.sandbox(profile='full', target=str(tmp_path)) as run:
        try:
            raise RuntimeError('unrelated caller exception')
        except RuntimeError:
            with pytest.raises(BaseException) as caught:
                run(['/bin/true'], input=b'owned input', capture_output=True, timeout=1)
    assert caught.value is (primary if preparation_fails else cleanup)
    assert not calls
    assert len(writers) == 1 and writers[0].closed
    assert len(readers) == (0 if preparation_fails else 1)
    assert all(stream.closed for stream in readers)

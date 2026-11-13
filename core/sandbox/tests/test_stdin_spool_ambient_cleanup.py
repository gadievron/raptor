"""Input-spool cleanup must distinguish local failure from a caller handler."""
import builtins
import subprocess
import sys

import pytest

from core.sandbox import context
from core.sandbox.tests.test_context_decision_pins import _Driver
from core.testing.module_bindings import patch_module_attribute
from core.testing.state_isolation import pin_user_state_dirs

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux input spooling')


@pytest.mark.parametrize('backend_fails', [False, True], ids=['success', 'local-failure'])
def test_spool_close_failure_is_not_hidden_by_caller_exception(monkeypatch, tmp_path, backend_fails):
    cleanup = OSError('owned readonly spool close failure')
    primary = ValueError('owned backend failure')
    streams, calls, closes = [], [], []

    class Input:
        def __init__(self, stream):
            self.stream = stream

        def __getattr__(self, name):
            return getattr(self.stream, name)

        def close(self):
            if not self.stream.closed:
                self.stream.close()
                closes.append(True)
                raise cleanup

    def open_spool(path, *args, **kwargs):
        stream = builtins.open(path, *args, **kwargs)
        if str(path).startswith('/proc/self/fd/') and args == ('rb',):
            stream = Input(stream)
            streams.append(stream)
        return stream

    def backend(cmd, **kwargs):
        calls.append(True)
        assert kwargs['stdin'].read() == b'owned input'
        if backend_fails:
            raise primary
        result = subprocess.CompletedProcess(cmd, 0, None, None)
        result._setup_status = None
        return result

    def forbid_process(*args, **kwargs):
        pytest.fail('input ownership test must not launch a process')

    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    _Driver(monkeypatch, backend)
    monkeypatch.setattr(context, 'open', open_spool, raising=False)
    monkeypatch.setattr(context, '_run_teardown_first_timeout', forbid_process)
    patch_module_attribute(monkeypatch, context, 'subprocess', 'Popen', forbid_process)
    with context.sandbox(profile='full', target=str(tmp_path)) as run:
        try:
            raise RuntimeError('unrelated caller exception')
        except RuntimeError:
            with pytest.raises(BaseException) as caught:
                run(['/bin/true'], input=b'owned input', capture_output=True, timeout=1)
    assert caught.value is (primary if backend_fails else cleanup)
    assert calls == [True] and closes == [True]
    assert len(streams) == 1 and streams[0].closed

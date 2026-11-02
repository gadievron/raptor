"""rr must not confuse namespace setup capabilities with host perf authority."""
import ctypes
import os
import subprocess
import sys

import pytest

from core.sandbox._rr_caps import _Header, make_capability_drop
from core.sandbox.seccomp import _make_seccomp_preexec, check_seccomp_available

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux capabilities')


def test_rr_exec_has_no_capabilities():
    if not check_seccomp_available():
        pytest.skip('seccomp unavailable')
    code = '''
import ctypes
class Header(ctypes.Structure):
    _fields_ = [('version', ctypes.c_uint32), ('pid', ctypes.c_int)]
class Data(ctypes.Structure):
    _fields_ = [(n, ctypes.c_uint32) for n in ('effective', 'permitted', 'inheritable')]
h = Header(0x20080522, 0)
d = (Data * 2)()
assert ctypes.CDLL(None).capget(ctypes.byref(h), d) == 0
assert not any(v.effective or v.permitted or v.inheritable for v in d)
'''
    result = subprocess.run([sys.executable, '-I', '-S', '-c', code],
                            preexec_fn=_make_seccomp_preexec('rr'),
                            capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr


class Function:
    def __init__(self, call):
        self.call = call

    def __call__(self, *args):
        return self.call(*args)


@pytest.mark.parametrize('root', [False, True])
def test_drop_clears_all_sets_and_locks_fixups_before_clear(monkeypatch, root):
    events = []
    sets = [0x3fffffff, 0x3fffffff, 1]
    def get(header, data):
        assert ctypes.cast(header, ctypes.POINTER(_Header)).contents.version == 0x20080522
        data[0].effective, data[0].permitted, data[0].inheritable = sets
        return 0
    def put(header, data):
        assert not any(v.effective or v.permitted or v.inheritable for v in data)
        events.append('clear')
        sets[:] = [0, 0, 0]
        return 0
    def prctl(operation, value, *unused):
        events.append((operation, value))
        return 0
    class Lib:
        capget = Function(get)
        capset = Function(put)
    lib = Lib()
    lib.prctl = prctl
    monkeypatch.setattr(os, 'geteuid', lambda: 0 if root else 65534)
    make_capability_drop(lib)()
    assert events == [(27, 0), (28, 15), 'clear']


def test_failed_drop_refuses_execution(monkeypatch):
    class Refused(Exception):
        pass
    class Lib:
        capget = Function(lambda *args: -1)
        capset = Function(lambda *args: pytest.fail('must not proceed after failed capget'))
    def stop(code):
        assert code == 126
        raise Refused
    monkeypatch.setattr(os, '_exit', stop)
    monkeypatch.setattr(os, 'write', lambda *args: None)
    with pytest.raises(Refused):
        make_capability_drop(Lib())()

"""Exercise descriptor ownership through an isolated caller declaration."""
import __future__
import ast
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
CFG = {'root': sys.argv[1]}
assert sys.flags.isolated and sys.dont_write_bytecode and sys.flags.optimize == 0
source = Path(CFG['root']) / 'core/atomic_fs/tests/test_fs_lock_bounded.py'
mode = sys.argv[2]
assert mode in {'second_open', 'event_checkpoint'}
output = Path(sys.argv[3])
work = output.parent / 'owned-work'
work.mkdir(mode=0o700)
lock = work / 'a.json.lock'
owned = []
closes = []
attempts = []
primary = OSError('controlled second open refused before effect') if mode == 'second_open' else RuntimeError('controlled Event setup checkpoint')
base_open, base_close = os.open, os.close

def audit(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.')) or event in {'os.system', 'os.fork', 'os.forkpty', 'os.posix_spawn', 'os.exec', '_posixsubprocess.fork_exec'} or (event == 'import' and args and str(args[0]).split('.')[0] in {'core', 'packages', 'fcntl', 'threading'}):
        attempts.append(event)
        raise PermissionError('outside owned second-open witness')
sys.addaudithook(audit)

def open_owned(path, flags):
    assert path == str(lock) and flags == os.O_WRONLY
    if mode == 'second_open' and owned:
        assert len(owned) == 1
        raise primary
    assert len(owned) < 2
    fd = base_open(path, flags)
    owned.append((fd, os.fstat(fd)))
    return fd

def close_owned(fd):
    assert fd in [value for value, _identity in owned] and fd not in closes
    closes.append(fd)
    return base_close(fd)

def forbidden(*args, **kwargs):
    attempts.append('later caller seam')
    raise AssertionError('later FIFO/thread/lock seam reached')

def event_checkpoint():
    assert mode == 'event_checkpoint' and len(owned) == 2
    raise primary

fs_lock = SimpleNamespace()
class Patch:
    def setattr(self, obj, name, value, raising=True):
        assert obj is fs_lock and raising is False
        assert (name, value) in {('_ACQUIRE_DEADLINE_S', .5), ('_ACQUIRE_POLL_S', .05)}
        setattr(obj, name, value)

raw = source.read_text()
cls = next(n for n in ast.parse(raw).body if isinstance(n, ast.ClassDef) and n.name == 'TestHintContainment')
fn = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == 'test_fifo_swapped_at_lock_path_never_wedges_the_waiter')
assert len(fn.decorator_list) == 1 and ast.unparse(fn.decorator_list[0]).startswith('pytest.mark.skipif(')
fn.decorator_list = []
namespace = {'os': SimpleNamespace(open=open_owned, close=close_owned, O_WRONLY=os.O_WRONLY, unlink=forbidden, mkfifo=forbidden), 'fs_lock': fs_lock, 'threading': SimpleNamespace(Event=event_checkpoint, Thread=forbidden)}
exec(compile(ast.Module(body=[fn], type_ignores=[]), str(source), 'exec', flags=__future__.annotations.compiler_flag, dont_inherit=True), namespace)
record = None
try:
    try:
        namespace[fn.name](None, work, Patch())
    except BaseException as error:
        assert error is primary
    else:
        raise AssertionError('second-open refusal lost')
    expected = 1 if mode == 'second_open' else 2
    assert len(owned) == len(closes) == expected and not attempts
    for fd, _identity in owned:
        try:
            os.fstat(fd)
        except OSError as error:
            assert error.errno == 9
        else:
            raise AssertionError('caller left descriptor live')
    assert lock.stat().st_size == 0
    record = {'mode': mode, 'primary_identity': True, 'all_owned_fds_closed_before_rescue': True, 'caller_close_calls': len(closes), 'actual_open_count': len(owned), 'forbidden_attempts': attempts}
finally:
    for fd, identity in owned:
        if fd not in closes:
            current = os.fstat(fd)
            assert (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino)
            base_close(fd)
    lock.unlink(missing_ok=True)
    work.rmdir()
assert record is not None
record['independent_verified_rescue_complete'] = True
output.write_text(json.dumps(record, indent=2) + '\n')

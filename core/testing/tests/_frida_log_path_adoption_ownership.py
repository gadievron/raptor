"""Exact observation-log caller projection; no Frida or parser import."""
import __future__
import ast
import json
import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
CFG = {'root': sys.argv[1]}
assert sys.flags.isolated and sys.dont_write_bytecode and sys.flags.optimize == 0
source = Path(CFG['root']) / 'core/audit/tests/test_frida_observe.py'
mode = sys.argv[2]
assert mode in {'path_error', 'healthy'}
output = Path(sys.argv[3])
work = output.parent / 'owned-work'
work.mkdir(mode=0o700)
owned, closed, unlinked, conversions, attempts = [], [], [], [], []
primary = OSError('controlled before-effect Path conversion refusal')
base_close, base_unlink = os.close, os.unlink

def audit(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.')) or event in {'os.system', 'os.fork', 'os.forkpty', 'os.posix_spawn', 'os.exec', '_posixsubprocess.fork_exec'} or (event == 'import' and args and str(args[0]).split('.')[0] in {'core', 'packages', 'frida'}):
        attempts.append(event)
        raise PermissionError('outside owned observation-log projection')
sys.addaudithook(audit)

def allocate(*args, **kwargs):
    assert not args and kwargs == {'suffix': '.jsonl'} and not owned
    fd, name = tempfile.mkstemp(dir=work, **kwargs)
    owned.append((fd, name, os.fstat(fd)))
    return fd, name

def convert(name):
    assert len(owned) == 1 and name == owned[0][1] and not conversions
    conversions.append(name)
    if mode == 'path_error':
        raise primary
    return Path(name)

def close(fd):
    assert len(owned) == 1 and fd == owned[0][0] and not closed
    base_close(fd)
    closed.append(fd)

def unlink(name):
    assert len(owned) == 1 and name == owned[0][1] and not unlinked
    base_unlink(name)
    unlinked.append(name)

cls = next(n for n in ast.parse(source.read_text()).body if isinstance(n, ast.ClassDef) and n.name == 'TestParseObservations')
fn = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == '_write_log')
assert not fn.decorator_list and not fn.args.defaults
namespace = {'tempfile': SimpleNamespace(mkstemp=allocate), 'os': SimpleNamespace(close=close, unlink=unlink), 'Path': convert}
exec(compile(ast.Module(body=[fn], type_ignores=[]), str(source), 'exec', flags=__future__.annotations.compiler_flag, dont_inherit=True), namespace)
record = None
try:
    returned = None
    try:
        returned = namespace[fn.name](None, ['owned-call', 'owned-return'])
    except BaseException as error:
        assert mode == 'path_error' and error is primary
    else:
        assert mode == 'healthy'
    assert len(owned) == len(conversions) == len(closed) == 1 and not attempts
    fd, name, identity = owned[0]
    try:
        os.fstat(fd)
    except OSError as error:
        assert error.errno == 9
    else:
        raise AssertionError('caller left fd live')
    text = None
    caller_cleanup = 0
    if mode == 'path_error':
        assert returned is None and unlinked == [name] and not os.path.exists(name)
    else:
        assert type(returned) is type(Path()) and returned == Path(name) and not unlinked
        current = returned.stat()
        assert (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino)
        text = returned.read_text()
        assert text == 'owned-call\nowned-return'
        returned.unlink()
        caller_cleanup = 1
        assert not os.path.exists(name)
    record = {'mode': mode, 'expected_outcome_identity': True, 'fd_closed_before_rescue': True, 'path_absent_before_rescue': True, 'caller_close_calls': len(closed), 'raw_unlink_calls': len(unlinked), 'path_conversion_calls': len(conversions), 'written_text': text, 'success_transfer_then_caller_cleanup': caller_cleanup, 'forbidden_attempts': attempts}
finally:
    for fd, name, identity in owned:
        if fd not in closed:
            current = os.fstat(fd)
            assert (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino)
            base_close(fd)
        if os.path.exists(name):
            current = os.stat(name)
            assert (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino)
            base_unlink(name)
    work.rmdir()
assert record is not None
record['independent_verified_rescue_complete'] = True
output.write_text(json.dumps(record, indent=2) + '\n')

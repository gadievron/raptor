"""Project one fixture and its real sweep function into owned file resources."""
import __future__
import ast
import builtins
import glob
import hashlib
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from types import ModuleType, SimpleNamespace

HERE = Path(__file__).resolve().parent
CFG = {'root': None, 'sweep_source_sha256': 'f57d7fac26dafc5b39afdb0b69aa3922612ff0280cfdd1752e94792c9054e9f2', 'sweep_function_sha256': '34abcd6af67257d91c685f1c38de0b521b1a2a2d90fdb85c871233ef7b973b78'}
CFG['root'] = sys.argv[1]
assert sys.flags.isolated and sys.dont_write_bytecode and sys.flags.optimize == 0
root = Path(CFG['root'])
source = root / 'core/sandbox/tests/test_audit_failure_modes.py'
sweep_source = root / 'core/sandbox/_spawn.py'
assert hashlib.sha256(sweep_source.read_bytes()).hexdigest() == CFG['sweep_source_sha256']
mode = sys.argv[2]
assert mode in {'write_error', 'healthy'}
output = Path(sys.argv[3])
scratch = Path(os.environ['TMPDIR'])
assert scratch.is_dir() and tempfile.gettempdir() == str(scratch) and not list(scratch.iterdir())
owned, closed, writes, actual_writes, aged = [], [], [], [], []
active = {}
caller_unlinks, caller_missing, sweep_lstats, sweep_unlinks, sweep_calls = [], [], [], [], []
imports, attempts = [], []
primary = OSError('controlled before-effect stale-file write refusal')
base_close, base_unlink, base_lstat = os.close, os.unlink, os.lstat

def audit(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.')) or event in {'os.system', 'os.fork', 'os.forkpty', 'os.posix_spawn', 'os.exec', '_posixsubprocess.fork_exec'} or (event == 'import' and args and str(args[0]).split('.')[0] in {'core', 'packages'}):
        attempts.append(event)
        raise PermissionError('outside owned stale-audit projection')
sys.addaudithook(audit)

def index_for_path(name):
    matches = [i for i, (_, path, _) in enumerate(owned) if path == name]
    assert len(matches) == 1
    return matches[0]

def verify_path(name):
    index = index_for_path(name)
    identity = owned[index][2]
    current = base_lstat(name)
    assert (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino)
    return index

def allocate(*args, **kwargs):
    assert not args and kwargs == {'prefix': 'raptor-audit-cfg-test-', 'suffix': '.json', 'dir': str(scratch)} and len(owned) < 3
    fd, name = tempfile.mkstemp(**kwargs)
    assert fd not in active
    index = len(owned)
    owned.append((fd, name, os.fstat(fd)))
    active[fd] = index
    return fd, name

def write(fd, data):
    assert fd in active and data == b'{}'
    index = active[fd]
    writes.append(index)
    if mode == 'write_error':
        raise primary
    count = os.write(fd, data)
    actual_writes.append({'index': index, 'bytes': count})
    return count

def close(fd):
    assert fd in active
    index = active[fd]
    current, identity = os.fstat(fd), owned[index][2]
    assert (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino)
    base_close(fd)
    del active[fd]
    closed.append(index)

def utime(name, stamps):
    index = verify_path(name)
    assert index in closed and index not in aged
    assert stamps[0] == stamps[1] and time.time() - stamps[0] >= 3600
    os.utime(name, stamps)
    aged.append(index)

def caller_unlink(name):
    index = index_for_path(name)
    assert index in closed
    caller_unlinks.append(index)
    if os.path.lexists(name):
        verify_path(name)
    try:
        base_unlink(name)
    except FileNotFoundError:
        caller_missing.append(index)
        raise

def exists(name):
    index_for_path(name)
    return os.path.exists(name)

def sweep_getuid():
    assert len(owned) == len(closed) == len(aged) == 3 and not active and not sweep_calls
    assert set(glob.glob(str(scratch / 'raptor-audit-cfg-*.json'))) == {name for _, name, _ in owned}
    sweep_calls.append(True)
    return os.getuid()

def sweep_lstat(name):
    index = verify_path(name)
    assert index not in sweep_lstats
    sweep_lstats.append(index)
    return base_lstat(name)

def sweep_unlink(name):
    index = verify_path(name)
    assert index in sweep_lstats and index not in sweep_unlinks
    base_unlink(name)
    sweep_unlinks.append(index)

module = ModuleType('_owned_stale_audit_sweep')
base_import = builtins.__import__
def owned_import(name, globals=None, locals=None, fromlist=(), level=0):
    if name == 'core.sandbox._spawn':
        assert level == 0 and tuple(fromlist) == ('_sweep_stale_audit_configs',) and not imports
        imports.append(name)
        return module
    if name.split('.')[0] in {'core', 'packages'}:
        attempts.append('unapproved source import')
        raise PermissionError(name)
    return base_import(name, globals, locals, fromlist, level)
private_builtins = dict(vars(builtins), __import__=owned_import)
sweep_text = sweep_source.read_text()
sweep_fn = next(n for n in ast.parse(sweep_text).body if isinstance(n, ast.FunctionDef) and n.name == '_sweep_stale_audit_configs')
assert hashlib.sha256(ast.get_source_segment(sweep_text, sweep_fn).encode()).hexdigest() == CFG['sweep_function_sha256']
assert not sweep_fn.decorator_list and len(sweep_fn.args.defaults) == 1 and ast.literal_eval(sweep_fn.args.defaults[0]) == 3600.0
sweep_namespace = {'__builtins__': private_builtins, 'os': SimpleNamespace(getuid=sweep_getuid, lstat=sweep_lstat, unlink=sweep_unlink)}
exec(compile(ast.Module(body=[sweep_fn], type_ignores=[]), str(sweep_source), 'exec', flags=__future__.annotations.compiler_flag, dont_inherit=True), sweep_namespace)
module._sweep_stale_audit_configs = sweep_namespace[sweep_fn.name]
assert module._sweep_stale_audit_configs.__code__.co_filename == str(sweep_source)
cls = next(n for n in ast.parse(source.read_text()).body if isinstance(n, ast.ClassDef) and n.name == 'TestStaleAuditConfigSweep')
fn = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == 'test_sweep_removes_same_uid_stale_files')
assert not fn.decorator_list
namespace = {'__builtins__': private_builtins, 'os': SimpleNamespace(write=write, close=close, utime=utime, unlink=caller_unlink, path=SimpleNamespace(exists=exists)), 'time': time}
exec(compile(ast.Module(body=[fn], type_ignores=[]), str(source), 'exec', flags=__future__.annotations.compiler_flag, dont_inherit=True), namespace)
# The real tempfile module is used by both declarations; only its consumer
# mkstemp operation is owned through an exact imported module view.
stdlib_tempfile = tempfile
view = ModuleType('_owned_stale_fixture_tempfile')
view.mkstemp = allocate
view.gettempdir = stdlib_tempfile.gettempdir
original_import = owned_import
def fixture_import(name, globals=None, locals=None, fromlist=(), level=0):
    if name == 'tempfile' and globals is namespace:
        assert level == 0 and not fromlist
        return view
    return original_import(name, globals, locals, fromlist, level)
private_builtins['__import__'] = fixture_import  # Update the mapping cached by both owned functions.
record = None
try:
    try:
        namespace[fn.name](None, scratch)
    except BaseException as error:
        assert mode == 'write_error' and error is primary
    else:
        assert mode == 'healthy'
    expected = 1 if mode == 'write_error' else 3
    assert len(owned) == len(writes) == len(closed) == expected and sorted(closed) == list(range(expected)) and not active
    assert not attempts and len(imports) == 1
    for fd in {record[0] for record in owned}:
        try:
            os.fstat(fd)
        except OSError as error:
            assert error.errno == 9
        else:
            raise AssertionError('caller left descriptor live')
    assert not list(scratch.iterdir())
    if mode == 'write_error':
        assert not actual_writes and caller_unlinks == [0] and not caller_missing
        assert not sweep_calls and not sweep_lstats and not sweep_unlinks
    else:
        assert [entry['bytes'] for entry in actual_writes] == [2, 2, 2]
        assert len(sweep_calls) == 1 and sorted(sweep_lstats) == sorted(sweep_unlinks) == [0, 1, 2]
        assert caller_unlinks == caller_missing == [0, 1, 2]
    record = {'mode': mode, 'expected_outcome_identity': True, 'allocations': len(owned), 'closed_incarnations': len(closed), 'all_descriptors_closed_before_rescue': True, 'all_paths_absent_before_rescue': True, 'write_attempts': len(writes), 'written_bytes': [entry['bytes'] for entry in actual_writes], 'caller_unlink_attempts': len(caller_unlinks), 'caller_missing_unlinks': len(caller_missing), 'actual_sweep_calls': len(sweep_calls), 'actual_sweep_lstats': len(sweep_lstats), 'actual_sweep_unlinks': len(sweep_unlinks), 'exact_import_bindings': len(imports), 'actual_tempdir': str(scratch), 'actual_sweep_function_pin': CFG['sweep_function_sha256'], 'forbidden_attempts': attempts}
finally:
    for index, (fd, name, identity) in enumerate(owned):
        if index not in closed:
            current = os.fstat(fd)
            assert active.get(fd) == index and (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino)
            base_close(fd)
            del active[fd]
        if os.path.exists(name):
            verify_path(name)
            base_unlink(name)
    assert not active and not list(scratch.iterdir())
assert record is not None
record['independent_verified_rescue_complete'] = True
output.write_text(json.dumps(record, indent=2) + '\n')

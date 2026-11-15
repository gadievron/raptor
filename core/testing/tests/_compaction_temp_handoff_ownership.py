"""Exercise one compaction fixture callback without starting compaction."""
import __future__
import ast
from contextlib import ExitStack
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
CFG = {'producer_source_sha256': '35254ec115df30441b570d0a23ef84c0c1e8b92a694046daa0194b02f0057e56', 'prefix_declaration_sha256': '26190f2453f534001013245536db7e603069d7119dd24f72823a34baba3198af', 'prefix': '.~journal-compact-'}
CFG['root'] = sys.argv[1]
assert sys.flags.isolated and sys.dont_write_bytecode and sys.flags.optimize == 0
root = Path(CFG['root'])
source = root / 'core/coverage/tests/test_compaction_storage_lifecycle.py'
producer = root / 'core/coverage/journal_compact.py'
assert hashlib.sha256(producer.read_bytes()).hexdigest() == CFG['producer_source_sha256']
mode = sys.argv[2]
assert mode in {'wait_refusal', 'healthy'}
output = Path(sys.argv[3])
work = output.parent / 'owned-work'
work.mkdir(mode=0o700)
owned, closed, unlinked, signals, waits, order, attempts = [], [], [], [], [], [], []
temps = []
base_close, base_unlink = os.close, os.unlink

def audit(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.')) or event in {'os.system', 'os.fork', 'os.forkpty', 'os.posix_spawn', 'os.exec', '_posixsubprocess.fork_exec'} or (event == 'import' and args and str(args[0]).split('.')[0] in {'core', 'packages', 'threading', 'concurrent'}):
        attempts.append(event)
        raise PermissionError('outside owned compaction callback projection')
sys.addaudithook(audit)

producer_text = producer.read_text()
prefix = next(n for n in ast.parse(producer_text).body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == '_COMPACT_TMP_PREFIX' for t in n.targets))
assert hashlib.sha256(ast.get_source_segment(producer_text, prefix).encode()).hexdigest() == CFG['prefix_declaration_sha256']
assert ast.literal_eval(prefix.value) == CFG['prefix']

def allocate(*args, **kwargs):
    assert not args and kwargs == {'prefix': CFG['prefix'], 'suffix': '.jsonl', 'dir': str(work)} and not owned
    result = tempfile.mkstemp(**kwargs)
    owned.append((result, os.fstat(result[0])))
    return result

def close(fd):
    assert len(owned) == 1 and fd == owned[0][0][0] and not closed
    current, identity = os.fstat(fd), owned[0][1]
    assert (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino)
    base_close(fd)
    closed.append(fd)
    order.append('close')

def unlink(name):
    assert len(owned) == 1 and name == owned[0][0][1] and not unlinked
    current, identity = os.lstat(name), owned[0][1]
    assert (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino)
    base_unlink(name)
    unlinked.append(name)
    order.append('unlink')

def signal():
    assert len(owned) == len(temps) == 1 and not signals
    signals.append(True)

def wait(seconds):
    assert seconds == 5 and signals == [True] and not waits
    waits.append(seconds)
    return mode == 'healthy'

outer = next(n for n in ast.parse(source.read_text()).body if isinstance(n, ast.FunctionDef) and n.name == 'test_global_writer_lock_prevents_active_temp_reaping_and_redundant_generation')
fn = next(n for n in outer.body if isinstance(n, ast.FunctionDef) and n.name == 'held_temp')
assert not fn.decorator_list and not fn.args.defaults
namespace = {'mkstemp': allocate, 'temps': temps, 'Path': Path, 'entered': SimpleNamespace(set=signal), 'release': SimpleNamespace(wait=wait), 'os': SimpleNamespace(close=close, unlink=unlink), 'ExitStack': ExitStack}
exec(compile(ast.Module(body=[fn], type_ignores=[]), str(source), 'exec', flags=__future__.annotations.compiler_flag, dont_inherit=True), namespace)
record = None
caller_retired = []
try:
    returned = None
    try:
        returned = namespace[fn.name](prefix=CFG['prefix'], suffix='.jsonl', dir=str(work))
    except BaseException as error:
        assert mode == 'wait_refusal' and type(error) is AssertionError
        cursor = error.__traceback__
        frames = []
        while cursor is not None:
            frames.append((cursor.tb_frame.f_code.co_filename, cursor.tb_frame.f_code.co_name))
            cursor = cursor.tb_next
        assert (str(source), 'held_temp') in frames
    else:
        assert mode == 'healthy'
    assert len(owned) == len(temps) == len(signals) == 1 and waits == [5] and not attempts
    original_tuple, identity = owned[0]
    fd, name = original_tuple
    assert temps[0] == Path(name)
    if mode == 'wait_refusal':
        assert returned is None and closed == [fd] and unlinked == [name] and order == ['close', 'unlink']
        try:
            os.fstat(fd)
        except OSError as error:
            assert error.errno == 9
        else:
            raise AssertionError('fixture left descriptor live')
        assert not os.path.exists(name)
    else:
        assert returned is original_tuple and not closed and not unlinked and not order
        current, entry = os.fstat(fd), os.lstat(name)
        assert (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino) == (entry.st_dev, entry.st_ino)
        assert entry.st_size == 0
        base_close(fd)
        caller_retired.append(fd)
        base_unlink(name)
        assert not os.path.exists(name)
    try:
        os.fstat(fd)
    except OSError as error:
        assert error.errno == 9
    else:
        raise AssertionError('descriptor still live before rescue')
    record = {'mode': mode, 'expected_outcome': True, 'actual_caller_assertion': mode == 'wait_refusal', 'exact_tuple_live_handoff_before_caller_cleanup': mode == 'healthy', 'descriptor_closed_before_rescue': True, 'path_absent_before_rescue': True, 'fixture_close_calls': len(closed), 'fixture_unlink_calls': len(unlinked), 'handoff_caller_retirement_calls': len(caller_retired), 'signal_calls': len(signals), 'wait_seconds_arguments': waits, 'tracked_temp_paths': len(temps), 'underlying_prefix': CFG['prefix'], 'callback_order': order, 'forbidden_attempts': attempts}
finally:
    for (fd, name), identity in owned:
        if fd not in closed and fd not in caller_retired:
            current = os.fstat(fd)
            assert (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino)
            base_close(fd)
        if os.path.exists(name):
            current = os.lstat(name)
            assert (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino)
            base_unlink(name)
    work.rmdir()
assert record is not None
record['independent_verified_rescue_complete'] = True
output.write_text(json.dumps(record, indent=2) + '\n')

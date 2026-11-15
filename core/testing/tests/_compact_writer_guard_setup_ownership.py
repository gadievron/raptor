"""Guard-through-yield fixture region with opaque journal inputs."""
import __future__
import ast
from contextlib import ExitStack
import hashlib
import io
import json
import os
import sys
import tempfile
from pathlib import Path
from types import ModuleType, SimpleNamespace

HERE = Path(__file__).resolve().parent
CFG = {'source_sha256': '58063283371222943c4857815f9ba2e729a3d5d0224f813cfd98561e0ab33f74', 'prelude_sha256': '52b7e01b897040814a822de5f97642e30d5dc2dfe2d34eadd124b70c59879428'}
CFG['root'] = sys.argv[1]
assert sys.flags.isolated and sys.dont_write_bytecode and sys.flags.optimize == 0
source = Path(CFG['root']) / 'core/coverage/tests/test_compact_writer_ownership.py'
assert hashlib.sha256(source.read_bytes()).hexdigest() == CFG['source_sha256']
mode = sys.argv[2]
assert mode in {'binding_error', 'healthy'}
output = Path(sys.argv[3])
work = output.parent / 'owned-work'
work.mkdir(mode=0o700)
journal = work / 'opaque-journal-input'
journal.write_bytes(b'owned opaque prefix input\n')
original = journal.read_bytes()
owned, closed, binding_calls, history, attempts, close_order = [], [], [], [], [], []
primary = MemoryError('controlled private binding allocation refusal')
base_open, base_close = os.open, os.close
consumer = ModuleType('_owned_compact_fixture_consumer')
consumer.tempfile, consumer.os = tempfile, os
initial = {'tempfile': consumer.tempfile, 'os': consumer.os}

def audit(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.')) or event in {'os.system', 'os.fork', 'os.forkpty', 'os.posix_spawn', 'os.exec', '_posixsubprocess.fork_exec'} or (event == 'import' and args and str(args[0]).split('.')[0] in {'core', 'packages', 'pytest'}):
        attempts.append(event)
        raise PermissionError('outside owned guard fixture region')
sys.addaudithook(audit)

def open_guard(path, flags):
    assert Path(path) == work / 'owned-guard' and flags == os.O_RDONLY and not owned
    fd = base_open(path, flags)
    owned.append(('guard', fd, str(path), os.fstat(fd)))
    return fd

def allocate_dynamic(*args, **kwargs):
    assert mode == 'healthy' and len(owned) == 1 and not args
    assert kwargs == {'prefix': 'owned-rewrite-', 'suffix': '.jsonl', 'dir': str(work)}
    fd, name = tempfile.mkstemp(**kwargs)
    assert fd != owned[0][1]
    owned.append(('dynamic', fd, name, os.fstat(fd)))
    return fd, name

def close(fd):
    matches = [item for item in owned if item[1] == fd]
    assert len(matches) == 1 and fd not in closed
    label, _, _, identity = matches[0]
    current = os.fstat(fd)
    assert (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino)
    if label == 'guard' and mode == 'healthy':
        assert any(item[0] == 'dynamic' and item[1] in closed for item in owned)
    base_close(fd)
    closed.append(fd)
    close_order.append(label)

view = ModuleType('_owned_fixture_os')
view.__dict__.update(vars(os))
view.open, view.close = open_guard, close

class Patch:
    def setattr(self, target, name, value):
        assert target is consumer and name in {'tempfile', 'os'}
        binding_calls.append(name)
        assert binding_calls == ['tempfile', 'os'][:len(binding_calls)]
        assert isinstance(value, SimpleNamespace)
        if name == 'tempfile':
            assert callable(value.mkstemp)
        else:
            assert callable(value.close) and callable(value.fdopen)
        if mode == 'binding_error':
            assert binding_calls == ['tempfile'] and not history
            raise primary
        history.append((target, name, getattr(target, name)))
        setattr(target, name, value)
    def undo(self):
        while history:
            target, name, value = history.pop()
            setattr(target, name, value)

text = source.read_text()
fn = next(n for n in ast.parse(text).body if isinstance(n, ast.FunctionDef) and n.name == 'rewrite')
assert len(fn.decorator_list) == 1 and ast.unparse(fn.decorator_list[0]) == 'pytest.fixture'
assert hashlib.sha256('\n'.join(ast.get_source_segment(text, n) for n in fn.body[:3]).encode()).hexdigest() == CFG['prelude_sha256']
assert ast.unparse(fn.body[0]).startswith('_reemission_run(tmp_path,')
assert ast.unparse(fn.body[1]) == 'journal = tmp_path / JOURNAL_FILENAME'
assert ast.unparse(fn.body[2]) == 'original = journal.read_bytes()'
fn.decorator_list = []
fn.body = fn.body[3:]
dynamic_tempfile = ModuleType('_owned_dynamic_fixture_tempfile')
dynamic_tempfile.mkstemp = allocate_dynamic
namespace = {'Path': Path, 'journal': journal, 'original': original, 'compact': consumer, 'os': view, 'tempfile': dynamic_tempfile, 'io': io, 'SimpleNamespace': SimpleNamespace, 'ExitStack': ExitStack}
exec(compile(ast.Module(body=[fn], type_ignores=[]), str(source), 'exec', flags=__future__.annotations.compiler_flag, dont_inherit=True), namespace)
patch = Patch()
generator = namespace[fn.name](work, patch)
record = None
try:
    yielded = None
    try:
        yielded = next(generator)
    except BaseException as error:
        assert mode == 'binding_error' and error is primary
    else:
        assert mode == 'healthy' and type(yielded) is dict
    assert len(owned) == 1 and binding_calls == (['tempfile'] if mode == 'binding_error' else ['tempfile', 'os'])
    label, guard_fd, guard_name, identity = owned[0]
    if mode == 'binding_error':
        assert generator.gi_frame is None and closed == [guard_fd] and not history
    else:
        assert generator.gi_frame is not None and not closed
        assert yielded['root'] == work and yielded['journal'] == journal and yielded['original'] == original
        assert yielded['guard'] == guard_fd and yielded['live'] == set()
        current = os.fstat(guard_fd)
        assert (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino)
        assert os.pread(guard_fd, 64, 0) == b'owned unrelated descriptor'
        dynamic_fd, dynamic_name = consumer.tempfile.mkstemp(prefix='owned-rewrite-', suffix='.jsonl', dir=str(work))
        assert yielded['live'] == {dynamic_fd} and yielded['fd'] == dynamic_fd and yielded['temporary'] == dynamic_name
        assert os.fstat(dynamic_fd).st_size == 0 and os.pread(guard_fd, 64, 0) == b'owned unrelated descriptor'
        try:
            next(generator)
        except StopIteration as complete:
            assert complete.value is None
        else:
            raise AssertionError('fixture generator did not complete')
        assert generator.gi_frame is None and yielded['live'] == set()
        assert close_order == ['dynamic', 'guard']
    patch.undo()
    assert consumer.tempfile is initial['tempfile'] and consumer.os is initial['os'] and not history
    assert not attempts and len(closed) == len(owned)
    for label, fd, name, identity in owned:
        try:
            os.fstat(fd)
        except OSError as error:
            assert error.errno == 9
        else:
            raise AssertionError('fixture left descriptor live before rescue')
    assert Path(guard_name).read_bytes() == b'owned unrelated descriptor'
    record = {'mode': mode, 'expected_outcome_identity': True, 'yield_reached': mode == 'healthy', 'guard_live_at_yield': mode == 'healthy', 'dynamic_owned_then_retired': mode == 'healthy', 'all_raw_descriptors_closed_before_rescue': True, 'raw_guard_close_calls': close_order.count('guard'), 'raw_dynamic_close_calls': close_order.count('dynamic'), 'binding_calls': binding_calls, 'private_bindings_restored': True, 'generator_complete': generator.gi_frame is None, 'guard_file_fixture_owned': True, 'opaque_journal_prelude_excluded': True, 'close_order': close_order, 'forbidden_attempts': attempts}
finally:
    if generator.gi_frame is not None:
        generator.close()
    patch.undo()
    for label, fd, name, identity in owned:
        if fd not in closed:
            current = os.fstat(fd)
            assert (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino)
            base_close(fd)
        if os.path.exists(name):
            current = os.stat(name)
            assert (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino)
            Path(name).unlink()
    journal.unlink()
    work.rmdir()
assert record is not None
record['independent_verified_rescue_complete'] = True
output.write_text(json.dumps(record, indent=2) + '\n')

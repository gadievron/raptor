from pathlib import Path
import os
import socket
import subprocess
import sys
import threading
from types import ModuleType

# This owned interpreter may execute only in-process Python/file operations.
denied_calls = []
def denied(*args, **kwargs):
    denied_calls.append('native_or_transport')
    raise AssertionError('unexpected child launch or transport')
subprocess.Popen = denied
for name in ('fork', 'forkpty', 'system', 'posix_spawn', 'posix_spawnp', 'execv', 'execve', 'execvp', 'execvpe'):
    if hasattr(os, name):
        setattr(os, name, denied)
socket.socket.connect = denied
socket.socket.connect_ex = denied
root, scratch = map(Path, sys.argv[1:3])
sys.path.insert(0, str(root))
# Match the reviewed Linux process-libc bootstrap; never discover native tools.
import ctypes.util
from unittest.mock import patch
with patch.object(ctypes.util, 'find_library', side_effect=lambda name: None if name == 'c' else denied()):
    from core.sandbox import preexec
    assert preexec._get_libc() is not None
from core.config import RaptorConfig
RaptorConfig.LOG_DIR = scratch / 'logs'
import atexit
import stat
import pytest
from contextlib import contextmanager
from core.testing.module_views import module_function_view
from core.llm.tests import test_cc_adapter as native
from core.llm import cc_adapter
from core.run import scratch as scratch_mod
error_name, stage, after_text = sys.argv[3:6]
after = after_text == 'True'
error = {'RuntimeError': RuntimeError, 'KeyboardInterrupt': KeyboardInterrupt, 'none': None}[error_name]
failure = error('owned neutral-cwd worker fault') if error else None
workers, barriers, fired, worker_errors, callbacks, allocations = [], [], [], [], [], []
waiting = threading.Event()
class Barrier(threading.Barrier):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        barriers.append(self)
    def wait(self, *args, **kwargs):
        waiting.set()
        return super().wait(*args, **kwargs)
class Worker(threading.Thread):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        workers.append(self)
    def run(self):
        try:
            super().run()
        except threading.BrokenBarrierError as caught:
            worker_errors.append(caught)
    def start(self):
        selected = stage == 'start' and not fired
        if selected and not after:
            fired.append(True)
            raise failure
        super().start()
        if selected:
            assert waiting.wait(5)
            fired.append(True)
            raise failure
    def join(self, timeout=None):
        selected = stage == 'join' and not fired
        if selected and not after:
            fired.append(True)
            raise failure
        result = super().join(timeout=timeout)
        if selected:
            fired.append(True)
            raise failure
        return result
thread_view = ModuleType('threading')
vars(thread_view).update(vars(threading))
thread_view.Thread, thread_view.Barrier = Worker, Barrier
scratch_view = ModuleType('core.run.scratch')
vars(scratch_view).update(vars(scratch_mod))
@contextmanager
def owned_scratch(prefix, **kwargs):
    assert prefix == 'raptor-cc-cwd-' and not kwargs
    with scratch_mod.scratch_dir(prefix, dir=scratch / 'allocations') as path:
        allocations.append(path)
        yield path
scratch_view.scratch_dir = owned_scratch
exit_view = ModuleType('atexit')
vars(exit_view).update(vars(atexit))
def register(callback):
    callbacks.append(callback)
    return callback
exit_view.register = register
inherited_import = __import__
run_pkg, core_pkg = ModuleType('core.run'), ModuleType('core')
run_pkg.scratch = scratch_view
core_pkg.run = run_pkg
def production_import(name, globals=None, locals=None, fromlist=(), level=0):
    if not level and name == 'atexit':
        return exit_view
    if not level and name == 'core.run.scratch':
        return scratch_view if fromlist else core_pkg
    return inherited_import(name, globals, locals, fromlist, level)
borrowed_cwd, borrowed_lock = cc_adapter._neutral_cwd, cc_adapter._neutral_cwd_lock
cc_view = module_function_view(cc_adapter, bindings={'_neutral_cwd': None, '_neutral_cwd_lock': threading.Lock()}, import_hook=production_import)
assert cc_view.neutral_cwd.__code__ is cc_adapter.neutral_cwd.__code__
llm_pkg = ModuleType('core.llm')
llm_pkg.cc_adapter = cc_view
def native_import(name, globals=None, locals=None, fromlist=(), level=0):
    if not level and name == 'threading':
        return thread_view
    if not level and name == 'core.llm.cc_adapter':
        return cc_view
    if not level and name == 'core.llm':
        return llm_pkg
    if not level and name == 'core.run.scratch':
        return scratch_view if fromlist else core_pkg
    return inherited_import(name, globals, locals, fromlist, level)
view = module_function_view(native, bindings={'_owned_native': native.TestNeutralCwd.test_concurrent_first_calls_create_one_dir, '_owned_positive': native.TestNeutralCwd.test_creates_private_dir_once}, import_hook=native_import)
assert view._owned_native.__code__ is native.TestNeutralCwd.test_concurrent_first_calls_create_one_dir.__code__
patcher = pytest.MonkeyPatch()
try:
    try:
        if stage == 'control':
            view._owned_positive(native.TestNeutralCwd())
        else:
            view._owned_native(native.TestNeutralCwd(), patcher)
    except BaseException as caught:
        assert failure is not None and caught is failure
    else:
        assert failure is None
    assert fired == ([True] if failure else [])
    assert (len(workers), len(barriers)) == ((0, 0) if stage == 'control' else (8, 1))
    assert not any(worker.is_alive() for worker in workers)
    assert not worker_errors
    if stage in {'normal', 'join', 'control'}:
        assert len(allocations) == len(callbacks) == 1
        path = allocations[0]
        assert path.exists() and not list(path.iterdir())
        assert stat.S_IMODE(path.stat().st_mode) == 0o700
    else:
        assert not allocations and not callbacks
finally:
    for barrier in barriers:
        barrier.abort()
    for worker in workers:
        if worker.ident is not None:
            threading.Thread.join(worker, timeout=10)
            assert not worker.is_alive()
    for callback in reversed(callbacks):
        callback()
    patcher.undo()
assert all(not path.exists() for path in allocations)
assert cc_adapter._neutral_cwd is borrowed_cwd and cc_adapter._neutral_cwd_lock is borrowed_lock
assert not denied_calls, denied_calls
print('NEUTRAL_CWD_WORKER_OK')

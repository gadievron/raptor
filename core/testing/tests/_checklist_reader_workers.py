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
import inspect
import pytest
from core.inventory.tests import test_sharded_checklist as native
import core.atomic_fs.fs_lock as fs_lock
from core.testing.module_views import module_function_view
error_name, stage, after_text = sys.argv[3:6]
after = after_text == 'True'
error = {'RuntimeError': RuntimeError, 'KeyboardInterrupt': KeyboardInterrupt, 'none': None}[error_name]
failure = error('owned checklist reader worker fault') if error else None
workers, fired, acquisitions = [], [], []
acquired, release = threading.Event(), threading.Event()
main_ident = threading.get_ident()
real_try = fs_lock._try_flock_nb
lock = scratch / 'checklist.lock'
def gate_acquisition(fd):
    result = real_try(fd)
    if result and threading.get_ident() != main_ident:
        stamp = os.fstat(fd)
        assert (stamp.st_dev, stamp.st_ino) == (lock.stat().st_dev, lock.stat().st_ino)
        acquisitions.append((fd, stamp.st_dev, stamp.st_ino))
        acquired.set()
        assert release.wait(10), 'owned checklist acquisition was not released'
    return result
class Worker(threading.Thread):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        values = inspect.getclosurevars(kwargs['target']).nonlocals
        self.errors, self.got = values['errors'], values['got']
        self.contended = inspect.getclosurevars(fs_lock._try_flock_nb).nonlocals['contended']
        workers.append(self)
    def start(self):
        selected = stage == 'start' and not fired
        if selected and not after:
            fired.append(True)
            raise failure
        super().start()
        if selected:
            assert self.contended.wait(5)
            fired.append(True)
            raise failure
    def join(self, timeout=None):
        selected = stage == 'join' and not fired
        if selected and not after:
            assert acquired.wait(5)
            fired.append(True)
            raise failure
        release.set()
        result = super().join(timeout=timeout)
        if selected:
            fired.append(True)
            raise failure
        return result
thread_view = ModuleType('threading')
vars(thread_view).update(vars(threading))
thread_view.Thread = Worker
inherited_import = __import__
def import_local(name, globals=None, locals=None, fromlist=(), level=0):
    if not level and name == 'threading':
        return thread_view
    return inherited_import(name, globals, locals, fromlist, level)
view = module_function_view(native, bindings={'_owned_native': native.TestReadSideEffectFree.test_reader_still_locks_when_writer_lock_exists}, import_hook=import_local)
assert view._owned_native.__code__ is native.TestReadSideEffectFree.test_reader_still_locks_when_writer_lock_exists.__code__
with pytest.MonkeyPatch.context() as production_patch:
    production_patch.setattr(fs_lock, '_try_flock_nb', gate_acquisition)
    with pytest.MonkeyPatch.context() as body_patch:
        try:
            try:
                view._owned_native(native.TestReadSideEffectFree(), scratch, body_patch)
            except BaseException as caught:
                assert failure is not None and caught is failure
            else:
                assert failure is None
            assert fired == ([True] if failure else [])
            assert len(workers) == 1
            assert not workers[0].is_alive()
        finally:
            release.set()
            for worker in workers:
                if worker.ident is not None:
                    threading.Thread.join(worker, timeout=10)
                    assert not worker.is_alive()
            assert not workers[0].errors
            if workers[0].ident is not None:
                assert len(acquisitions) == 1
                assert workers[0].contended.is_set()
                assert workers[0].got and workers[0].got[0].get('target_path') == '/t'
            else:
                assert not acquisitions and not workers[0].got
assert fs_lock._try_flock_nb is real_try
assert not denied_calls, denied_calls
print('CHECKLIST_READER_WORKER_OK')

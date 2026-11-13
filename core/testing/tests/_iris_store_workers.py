import builtins
from pathlib import Path
import os
import socket
import subprocess
import sys
import threading
from types import ModuleType

# This owned interpreter may execute only in-process Python/file operations.
def denied(*args, **kwargs):
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
from core.iris.tests import test_store as native
from core.iris.store import load_specs
from core.testing.module_views import module_function_view
error = {'RuntimeError': RuntimeError, 'KeyboardInterrupt': KeyboardInterrupt, 'none': None}[sys.argv[3]]
method = sys.argv[4]
stage, after = sys.argv[5], sys.argv[6] == 'True'
failure = error('owned IRIS worker lifecycle fault') if error else None
fired = []
release, ready = threading.Event(), threading.Event()
workers, completed = [], []
class Worker(threading.Thread):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        workers.append(self)
    def run(self):
        ready.set()
        if stage != "normal":
            assert release.wait(10)
        super().run()
        completed.append(True)
    def start(self):
        if stage == 'start' and not after:
            fired.append(True)
            raise failure
        super().start()
        assert ready.wait(5)
        if stage == 'start':
            fired.append(True)
            raise failure
    def join(self, timeout=None):
        selected = stage == 'join' and not fired
        if selected and not after:
            fired.append(True)
            raise failure
        release.set()
        result = super().join(timeout=timeout)
        if selected:
            fired.append(True)
            raise failure
        return result
view = ModuleType('threading')
vars(view).update(vars(threading))
view.Thread = Worker
def importer(name, globals=None, locals=None, fromlist=(), level=0):
    if name == 'threading' and level == 0:
        return view
    return builtins.__import__(name, globals, locals, fromlist, level)
original = getattr(native.TestStoreLock, method)
owner = module_function_view(native, bindings={'_owned_case': original}, import_hook=importer)
assert owner._owned_case.__code__ is original.__code__
try:
    try:
        owner._owned_case(native.TestStoreLock(), scratch)
    except BaseException as caught:
        assert failure is not None and caught is failure
    else:
        assert failure is None
    assert fired == ([True] if failure else [])
    assert len(workers) == 1 and not workers[0].is_alive()
finally:
    release.set()
    for worker in workers:
        if worker.ident is not None:
            threading.Thread.join(worker, timeout=10)
            assert not worker.is_alive()
assert completed == ([] if stage == "start" and not after else [True])
rows = load_specs(scratch / 'project/run_001')
if method == 'test_persist_waits_for_lock_then_merges':
    assert {row.function for row in rows} == ({'early_writer'} if stage == 'start' and not after else {'early_writer', 'late_writer'})
else:
    assert {row.function for row in rows} == {'check_input'}
print('IRIS_WORKER_OK')

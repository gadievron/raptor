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
from core.testing.tests import test_concurrent_worker_ownership as native
from core.testing.module_views import module_function_view
error = {'RuntimeError': RuntimeError, 'KeyboardInterrupt': KeyboardInterrupt, 'none': None}[sys.argv[3]]
stage, after = sys.argv[4], sys.argv[5] == 'True'
if stage.startswith('control-'):
    _, finish, cleanup, count = stage.split('-')
    native.test_group_retires_every_worker(finish, cleanup, int(count))
    assert not denied_calls, denied_calls
    print('BORROWED_WORKER_OWNER_OK')
    sys.exit(0)
failure = error('owned borrowed-worker lifecycle fault') if error else None
workers, fired, joins = [], [], []
borrowed_threads = native.threading
class Worker(threading.Thread):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.stop_event = kwargs['target'].__self__
        assert isinstance(self.stop_event, threading.Event)
        workers.append(self)
    def start(self):
        selected = stage == 'start' and self is workers[0] and not fired
        if selected and not after:
            fired.append(True)
            raise failure
        super().start()
        if selected:
            fired.append(True)
            raise failure
    def join(self, timeout=None):
        joins.append(self)
        selected = stage == 'join' and self is workers[0] and not fired
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
thread_view.Thread = Worker
owner = module_function_view(native, bindings={'threading': thread_view})
assert owner.test_group_retires_every_worker.__code__ is native.test_group_retires_every_worker.__code__
assert owner.retiring_threads is native.retiring_threads
try:
    try:
        owner.test_group_retires_every_worker('normal', 'none', 1)
    except BaseException as caught:
        assert failure is not None and caught is failure
    else:
        assert failure is None
    assert fired == ([True] if failure else [])
    assert len(workers) == (1 if stage == 'start' else 2)
    assert all(not worker.is_alive() and worker.stop_event.is_set() for worker in workers)
    if stage == 'start' and not after:
        assert workers[0].ident is None and not joins
finally:
    for worker in workers:
        worker.stop_event.set()
        if worker.ident is not None:
            threading.Thread.join(worker, timeout=2)
            assert not worker.is_alive()
assert native.threading is borrowed_threads
assert not denied_calls, denied_calls
print('BORROWED_WORKER_OWNER_OK')

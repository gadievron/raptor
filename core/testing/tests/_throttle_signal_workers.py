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
from core.llm.tests import test_throttle as native
from core.testing.module_views import module_function_view
error = {'RuntimeError': RuntimeError, 'KeyboardInterrupt': KeyboardInterrupt, 'none': None}[sys.argv[3]]
position, after, stage = int(sys.argv[4]), sys.argv[5] == 'True', sys.argv[6]
failure = error('owned throttle signal worker lifecycle fault') if error else None
fired = []
release, ready = threading.Event(), threading.Event()
workers, throttles, completed = [], [], []
registry = native._active_throttles
members = tuple(registry)
class Worker(threading.Thread):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.position = len(workers)
        workers.append(self)
    def run(self):
        ready.set()
        if stage != "normal":
            assert release.wait(10)
        super().run()
        completed.append(True)
    def start(self):
        selected = stage == 'start' and self.position == position
        if selected and not after:
            fired.append(True)
            raise failure
        super().start()
        if selected:
            assert ready.wait(5)
            fired.append(True)
            raise failure
    def join(self, timeout=None):
        selected = stage == 'join' and self.position == position and not fired
        if selected and not after:
            fired.append(True)
            raise failure
        release.set()
        value = super().join(timeout=timeout)
        if selected:
            fired.append(True)
            raise failure
        return value
view = ModuleType('threading')
vars(view).update(vars(threading))
view.Thread = Worker
def throttle(*args, **kwargs):
    assert args == (64,) and kwargs == {'auto_register': False}
    value = native.AdaptiveThrottle(*args, **kwargs)
    throttles.append(value)
    return value
original = native.TestBroadcastRegistry.test_thread_safety
owner = module_function_view(native, bindings={'threading': view, 'AdaptiveThrottle': throttle, '_owned_case': original})
assert owner._owned_case.__code__ is original.__code__
try:
    try:
        owner._owned_case(native.TestBroadcastRegistry())
    except BaseException as caught:
        assert failure is not None and caught is failure
    else:
        assert failure is None
    assert fired == ([True] if failure else [])
    assert len(workers) == 4 and all(not worker.is_alive() for worker in workers)
finally:
    release.set()
    for worker in workers:
        if worker.ident is not None:
            threading.Thread.join(worker, timeout=10)
            assert not worker.is_alive()
started = [worker for worker in workers if worker.ident is not None]
assert len(completed) == len(started) and throttles[0].signal_count == 50 * len(started)
assert native._active_throttles is registry and tuple(registry) == members
print('THROTTLE_SIGNAL_WORKER_OK')

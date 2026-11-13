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
failure = error('owned throttle restore worker fault') if error else None
fired, completed = [], []
workers, events, throttles = [], [], []
registry = native._active_throttles
members = tuple(registry)
class Worker(threading.Thread):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.position = len(workers)
        workers.append(self)
    def run(self):
        super().run()
        completed.append(self.position)
    def start(self):
        selected = stage == 'start' and self.position == position
        if selected and not after:
            fired.append(True)
            raise failure
        super().start()
        if selected:
            if self.position == 0:
                assert events[0].wait(5)
            fired.append(True)
            raise failure
    def join(self, timeout=None):
        selected = stage == 'join' and self.position == position and not fired
        if selected and not after:
            fired.append(True)
            raise failure
        value = super().join(timeout=timeout)
        if selected:
            fired.append(True)
            raise failure
        return value
view = ModuleType('threading')
vars(view).update(vars(threading))
view.Thread = Worker
def event():
    value = threading.Event()
    events.append(value)
    return value
view.Event = event
def throttle(*args, **kwargs):
    assert args == (2,) and kwargs['cooldown_s'] == 60.0 and kwargs['auto_register'] is False
    assert isinstance(kwargs['clock'], native._FakeMonotonic)
    value = native.AdaptiveThrottle(*args, **kwargs)
    throttles.append(value)
    return value
original = native.TestAcquireSync.test_restore_unblocks
owner = module_function_view(native, bindings={'threading': view, 'AdaptiveThrottle': throttle, '_owned_case': original})
assert owner._owned_case.__code__ is original.__code__
try:
    try:
        owner._owned_case(native.TestAcquireSync())
    except BaseException as caught:
        assert failure is not None and caught is failure
    else:
        assert failure is None
    assert fired == ([True] if failure else [])
    assert len(events) == 3 and len(workers) == 2
    assert all(not worker.is_alive() for worker in workers)
    assert events[1].is_set() and throttles[0].in_flight == 0
    assert sorted(completed) == [worker.position for worker in workers if worker.ident is not None]
    if stage == 'normal':
        assert events[2].is_set() and throttles[0].effective_workers == 2
finally:
    if len(events) > 1:
        events[1].set()
    for worker in workers:
        if worker.ident is not None:
            threading.Thread.join(worker, timeout=10)
            assert not worker.is_alive()
assert throttles[0].in_flight == 0
assert native._active_throttles is registry and tuple(registry) == members
print('THROTTLE_RESTORE_WORKER_OK')

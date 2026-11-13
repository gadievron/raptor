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
from packages.source_intel.tests import test_cache_invalidation as native
from core.testing.module_views import module_function_view
import pytest
error = {'RuntimeError': RuntimeError, 'KeyboardInterrupt': KeyboardInterrupt, 'none': None}[sys.argv[3]]
position, after = int(sys.argv[4]), sys.argv[5] == 'True'
stage = sys.argv[6]
failure = error('owned source cache worker lifecycle fault') if error else None
fired = []
workers, stops = [], []
ready = threading.Event()
class Worker(threading.Thread):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.position = len(workers)
        workers.append(self)
    def run(self):
        ready.set()
        super().run()
    def start(self):
        selected = stage == "start" and self.position == position
        if selected and not after:
            if self.position:
                assert ready.wait(5)
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
    stops.append(value)
    return value
view.Event = event
def importer(name, globals=None, locals=None, fromlist=(), level=0):
    if name == 'threading' and level == 0:
        return view
    return builtins.__import__(name, globals, locals, fromlist, level)
from importlib import import_module
analyze = import_module("packages.source_intel.analyze")
borrowed = analyze._INVENTORY_BY_TARGET
with pytest.MonkeyPatch.context() as patch:
    fixture = native._reset_caches.__wrapped__(patch)
    next(fixture)
    counts = {'register': 0, 'lookup': 0}
    def register(*args, **kwargs):
        counts['register'] += 1
        return native._register_inventory(*args, **kwargs)
    def lookup(*args, **kwargs):
        counts['lookup'] += 1
        return native._lookup_cached_inventory(*args, **kwargs)
    owner = module_function_view(native, bindings={'_register_inventory': register, '_lookup_cached_inventory': lookup}, import_hook=importer)
    try:
        try:
            owner.test_concurrent_register_lookup_no_raise(scratch)
        except BaseException as caught:
            assert failure is not None and caught is failure
        else:
            assert failure is None
        assert fired == ([True] if failure else [])
        assert len(workers) == 8 and len(stops) == 1
        assert all(not worker.is_alive() for worker in workers)
        assert stops[0].is_set()
        if stage == "normal":
            assert counts["register"] > 0 and counts["lookup"] > 0
    finally:
        for stop in stops:
            stop.set()
        for worker in workers:
            if worker.ident is not None:
                threading.Thread.join(worker, timeout=10)
                assert not worker.is_alive()
        fixture.close()
        assert analyze._INVENTORY_BY_TARGET is borrowed
print('SOURCE_CACHE_WORKER_OK')

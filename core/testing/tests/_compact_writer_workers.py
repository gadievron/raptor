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
from core.json.tests import test_reap_completion as native
from core import atomic_fs
from core.testing.module_views import module_function_view
from core.testing.state_isolation import pin_user_state_dirs
import pytest
error = {'RuntimeError': RuntimeError, 'KeyboardInterrupt': KeyboardInterrupt, 'none': None}[sys.argv[3]]
stage, after = sys.argv[4], sys.argv[5] == 'True'
failure = error('owned compact writer lifecycle fault') if error else None
reached, rescue = threading.Event(), threading.Event()
workers, publications, fired = [], [], []
borrowed_os = atomic_fs.os
os_view = ModuleType('os')
vars(os_view).update(vars(os))
def gated_replace(source, target, **kwargs):
    source, target = Path(source), Path(target)
    stamp = source.stat()
    publications.append((source, target, stamp.st_dev, stamp.st_ino))
    reached.set()
    assert rescue.wait(10), 'owned proof publication was not released'
    return os.replace(source, target, **kwargs)
os_view.replace = gated_replace
production = module_function_view(atomic_fs, bindings={'os': os_view})
assert production.write_bytes_atomically.__code__ is atomic_fs.write_bytes_atomically.__code__
class Worker(threading.Thread):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        values = inspect.getclosurevars(production.os.replace).nonlocals
        self.release, self.entered, self.staging = values['release'], values['entered'], values['staging']
        self.failures = inspect.getclosurevars(kwargs['target']).nonlocals['failures']
        workers.append(self)
    def start(self):
        if stage == 'start' and not after:
            fired.append(True)
            raise failure
        super().start()
        if stage == 'start':
            assert self.entered.wait(5)
            fired.append(True)
            raise failure
    def join(self, timeout=None):
        selected = stage == 'join' and not fired
        if selected and not after:
            assert reached.wait(5)
            fired.append(True)
            raise failure
        rescue.set()
        result = super().join(timeout=timeout)
        if selected:
            fired.append(True)
            raise failure
        return result
thread_view = ModuleType('threading')
vars(thread_view).update(vars(threading))
thread_view.Thread = Worker
owner = module_function_view(native, bindings={'threading': thread_view, 'atomic_fs': production})
assert owner.test_active_compact_writer_retains_its_staging_file.__code__ is native.test_active_compact_writer_retains_its_staging_file.__code__
with pytest.MonkeyPatch.context() as patch:
    pin_user_state_dirs(patch, scratch / 'state')
    try:
        try:
            owner.test_active_compact_writer_retains_its_staging_file(scratch, patch)
        except BaseException as caught:
            assert failure is not None and caught is failure
        else:
            assert failure is None
        assert fired == ([True] if failure else [])
        assert len(workers) == 1 and not workers[0].is_alive()
        assert workers[0].release.is_set() and not workers[0].failures
        started = workers[0].ident is not None
        assert len(publications) == int(started)
        if started:
            source, target, dev, ino = publications[0]
            assert workers[0].staging == [source]
            stamp = target.stat()
            assert (stamp.st_dev, stamp.st_ino) == (dev, ino)
            assert target.read_bytes() == b'{"value":1}' and not source.exists()
    finally:
        rescue.set()
        for worker in workers:
            worker.release.set()
            if worker.ident is not None:
                threading.Thread.join(worker, timeout=10)
                assert not worker.is_alive()
assert atomic_fs.os is borrowed_os and native.atomic_fs is atomic_fs
assert not denied_calls, denied_calls
print('COMPACT_WRITER_WORKER_OK')

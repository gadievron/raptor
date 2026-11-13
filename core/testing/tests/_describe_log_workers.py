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
from packages.describe.tests import test_deps as native
from core.testing.module_views import module_function_view
from core.testing.logging_state import isolated_cli_logging
import logging
import pytest
error = {'RuntimeError': RuntimeError, 'KeyboardInterrupt': KeyboardInterrupt, 'none': None}[sys.argv[3]]
stage, after = sys.argv[4], sys.argv[5] == 'True'
failure = error('owned describe logger worker lifecycle fault') if error else None
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
        assert tuple(logger.handlers) != values, "worker ran after capture handler retirement"
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
        value = super().join(timeout=timeout)
        if selected:
            fired.append(True)
            raise failure
        return value
view = ModuleType('threading')
vars(view).update(vars(threading))
view.Thread = Worker
def importer(name, globals=None, locals=None, fromlist=(), level=0):
    if name == 'threading' and level == 0:
        return view
    return builtins.__import__(name, globals, locals, fromlist, level)
original = native.TestThreadScopedSuppression.test_concurrent_threads_records_survive_window.__wrapped__
owner = module_function_view(native, bindings={'_owned_case': original}, import_hook=importer)
logger = logging.getLogger('packages.sca.discovery')
handlers = logger.handlers
values = tuple(handlers)
with pytest.MonkeyPatch.context() as patch, isolated_cli_logging(logger_names=('packages.sca.discovery',)):
    try:
        try:
            owner._owned_case(native.TestThreadScopedSuppression(), scratch, patch)
        except BaseException as caught:
            if error is RuntimeError and stage == 'start' and not after:
                # Existing best-effort demotion leaves the original record assertion.
                assert type(caught) is AssertionError
            else:
                assert error is KeyboardInterrupt and caught is failure
        else:
            assert error is not KeyboardInterrupt
            assert not (error is RuntimeError and stage == 'start' and not after)
        assert fired == ([True] if failure else [])
        assert len(workers) == 1 and not workers[0].is_alive()
        assert logger.handlers is handlers and tuple(handlers) == values
    finally:
        release.set()
        for worker in workers:
            if worker.ident is not None:
                threading.Thread.join(worker, timeout=10)
                assert not worker.is_alive()
assert completed == ([] if stage == "start" and not after else [True])
print('DESCRIBE_LOG_WORKER_OK')

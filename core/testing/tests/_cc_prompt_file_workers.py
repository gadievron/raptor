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
import stat
import pytest
from contextlib import contextmanager
from core.testing.module_views import module_function_view
from core.llm.tests import test_cc_adapter as native
from core.llm.tests import conftest as fixtures
from core.llm import cc_adapter
from core.run import scratch as scratch_module
error_name, stage, after_text, position_text = sys.argv[3:7]
after, position = after_text == 'True', int(position_text)
error = {'RuntimeError': RuntimeError, 'KeyboardInterrupt': KeyboardInterrupt, 'none': None}[error_name]
failure = error('owned prompt-file worker fault') if error else None
workers, fired, staged = [], [], []
entered, all_entered, release = threading.Event(), threading.Event(), threading.Event()
staged_lock = threading.Lock()
actual_prompt = native.system_prompt_file_for
@contextmanager
def gated_prompt(config):
    with actual_prompt(config) as path:
        assert path is not None and path.read_text() == 'race'
        with staged_lock:
            staged.append(path)
            entered.set()
            if len(staged) == 8:
                all_entered.set()
        assert release.wait(10), 'prompt-file use was not released'
        yield path
class Worker(threading.Thread):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.position = len(workers)
        values = inspect.getclosurevars(kwargs['target']).nonlocals
        self.errors, self.paths = values['errors'], values['paths']
        workers.append(self)
    def start(self):
        selected = stage == 'start' and self.position == position and not fired
        if selected and not after:
            fired.append(True)
            raise failure
        super().start()
        if selected:
            assert entered.wait(5)
            fired.append(True)
            raise failure
    def join(self, timeout=None):
        selected = stage == 'join' and self.position == position and not fired
        if selected and not after:
            assert all_entered.wait(5)
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
def native_import(name, globals=None, locals=None, fromlist=(), level=0):
    if not level and name == 'threading':
        return thread_view
    return inherited_import(name, globals, locals, fromlist, level)
view = module_function_view(native, bindings={'_owned_native': native.TestSystemPromptFileFor.test_concurrent_writers_one_file, 'system_prompt_file_for': gated_prompt}, import_hook=native_import)
assert view._owned_native.__code__ is native.TestSystemPromptFileFor.test_concurrent_writers_one_file.__code__
borrowed = {key: getattr(cc_adapter, key) for key in ('_sysprompt_cache', '_sysprompt_dir', '_sysprompt_owner_pid', '_sysprompt_lock')}
fixture_parent = scratch / 'prompt-cache'
with pytest.MonkeyPatch.context() as patcher:
    fixture = fixtures.sysprompt_cache.__wrapped__(scratch, patcher)
    cache = next(fixture)
    try:
        try:
            view._owned_native(native.TestSystemPromptFileFor())
        except BaseException as caught:
            assert failure is not None and caught is failure
        else:
            assert failure is None
        assert fired == ([True] if failure else [])
        assert len(workers) == 8
        assert not any(worker.is_alive() for worker in workers)
        if staged:
            assert len(set(staged)) == 1
            path = staged[0]
            assert path.read_text() == 'race'
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
            assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
        else:
            assert stage == 'start' and position == 0 and not after
    finally:
        release.set()
        for worker in workers:
            if worker.ident is not None:
                threading.Thread.join(worker, timeout=3)
                assert not worker.is_alive()
        assert all(not worker.errors for worker in workers)
        started = sum(worker.ident is not None for worker in workers)
        assert len(staged) == started
        assert len(workers[0].paths) == started
        assert all(path.read_text() == 'race' for path in staged)
        fixture.close()
        assert not fixture_parent.exists()
        assert not scratch_module._keepalive_paths
assert all(getattr(cc_adapter, key) is value for key, value in borrowed.items())
assert not denied_calls, denied_calls
print('CC_PROMPT_FILE_WORKER_OK')

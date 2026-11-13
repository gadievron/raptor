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
from core.llm.tests import conftest as fixtures
from core.llm.tests import test_system_prompt_cache_lifecycle as native
from core.testing.module_views import module_function_view
import pytest
error = {'RuntimeError': RuntimeError, 'KeyboardInterrupt': KeyboardInterrupt, 'none': None}[sys.argv[3]]
position, after, stage = int(sys.argv[4]), sys.argv[5] == 'True', sys.argv[6]
failure = error('owned prompt-cache worker fault') if error else None
release = threading.Event()
workers, completed, fired = [], [], []
class Worker(threading.Thread):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.position = len(workers)
        workers.append(self)
    def run(self):
        if self.position == 1:
            assert release.wait(10)
        super().run()
        completed.append(self.position)
    def start(self):
        selected = stage == 'start' and self.position == position
        if selected and not after:
            fired.append(True)
            raise failure
        super().start()
        if selected:
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
owner = module_function_view(native, bindings={'threading': view})
from core.llm import cc_adapter
borrowed = {key: getattr(cc_adapter, key) for key in ('_sysprompt_cache', '_sysprompt_dir', '_sysprompt_owner_pid', '_sysprompt_lock')}
with pytest.MonkeyPatch.context() as patch:
    fixture = fixtures.sysprompt_cache.__wrapped__(scratch, patch)
    cache = next(fixture)
    try:
        try:
            owner.test_concurrent_cleanup_and_creation_keep_new_owner(cache, patch)
        except BaseException as caught:
            assert failure is not None and caught is failure
        else:
            assert failure is None
        assert fired == ([True] if failure else [])
        assert len(workers) == 2 and all(not worker.is_alive() for worker in workers)
    finally:
        release.set()
        for worker in workers:
            if worker.ident is not None:
                threading.Thread.join(worker, timeout=10)
                assert not worker.is_alive()
        started = [worker.position for worker in workers if worker.ident is not None]
        assert sorted(completed) == started
        if 1 in started:
            assert cache._sysprompt_dir is not None
            assert any(path.read_text() == 'new' for path in cache._sysprompt_dir.iterdir() if path.is_file())
        elif 0 in started:
            assert cache._sysprompt_dir is None
        else:
            assert cache._sysprompt_dir is not None
            assert any(path.read_text() == 'old' for path in cache._sysprompt_dir.iterdir() if path.is_file())
        fixture.close()
assert all(getattr(cc_adapter, key) is value for key, value in borrowed.items())
print('PROMPT_CACHE_WORKER_OK')

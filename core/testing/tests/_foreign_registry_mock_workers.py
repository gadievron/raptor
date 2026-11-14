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
from core.testing.tests import test_module_registry_mocks as native
from core.testing.module_views import module_function_view
from core.testing.module_registry import module_registry_scope
error_name, stage, after_text = sys.argv[3:6]
after = after_text == 'True'
if stage.startswith('control-'):
    outcome = stage.removeprefix('control-')
    with pytest.MonkeyPatch.context() as patcher:
        native.test_native_dependency_mock_preserves_other_module_writers(native._SITES[0], 'borrowed', outcome, patcher)
    assert not denied_calls
    print('FOREIGN_REGISTRY_MOCK_OK')
    raise SystemExit(0)

error = {'RuntimeError': RuntimeError, 'KeyboardInterrupt': KeyboardInterrupt, 'none': None}[error_name]
failure = error('owned foreign mock publisher fault') if error else None
workers, fired, publications = [], [], []
entered, release = threading.Event(), threading.Event()
class Owner(pytest.MonkeyPatch):
    target = None
    def setitem(self, mapping, name, value):
        if mapping is sys.modules and name == self.target:
            entered.set()
            assert release.wait(10), 'foreign mock publication not released'
            publications.append(value)
        return super().setitem(mapping, name, value)
class Worker(threading.Thread):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        workers.append(self)
    def start(self):
        if stage == 'start' and not after:
            fired.append(True)
            raise failure
        super().start()
        if stage == 'start':
            assert entered.wait(5)
            fired.append(True)
            raise failure
    def join(self, timeout=None):
        selected = stage == 'join' and not fired
        if selected and not after:
            assert entered.wait(5)
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
view = module_function_view(native, bindings={'threading': thread_view})
assert view._foreign_changes.__code__ is native._foreign_changes.__code__
owner = Owner()
run, check = view._foreign_changes(owner)
publish = inspect.getclosurevars(run).nonlocals['publish']
values = inspect.getclosurevars(publish).nonlocals
names, published, replacement = values['names'], values['published'], values['replacement']
owner.target = names[0]
initial = {name: sys.modules.get(name) for name in names[1:]}
assert names[0] not in sys.modules
alias = names[0] + '_selected'
borrowed_threads, borrowed_table = native.threading, sys.modules
with pytest.MonkeyPatch.context() as prior:
    prior.setitem(sys.modules, alias, None)
    try:
        try:
            with module_registry_scope(alias) as selected:
                selected[alias] = ModuleType(alias)
                run()
        except BaseException as caught:
            assert failure is not None and caught is failure
        else:
            assert failure is None
        assert fired == ([True] if failure else [])
        assert sys.modules[alias] is None
        assert len(workers) == 1
        assert not workers[0].is_alive()
        started = workers[0].ident is not None
        if started:
            check()
            assert sys.modules[names[0]] is published
            assert sys.modules[names[1]] is replacement
            assert names[2] not in sys.modules
            assert publications == [published]
        else:
            assert names[0] not in sys.modules
            assert all(sys.modules[name] is value for name, value in initial.items())
            assert not publications
    finally:
        release.set()
        for worker in workers:
            if worker.ident is not None:
                threading.Thread.join(worker, timeout=5)
                assert not worker.is_alive()
        owner.undo()
    assert all(name not in sys.modules for name in names)
    assert sys.modules[alias] is None
assert alias not in sys.modules
assert sys.modules is borrowed_table and native.threading is borrowed_threads
assert not denied_calls, denied_calls
print('FOREIGN_REGISTRY_MOCK_OK')

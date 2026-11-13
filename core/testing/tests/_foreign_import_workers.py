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
from core.testing.tests import test_module_registry_ownership as native
from core.testing.module_views import module_function_view
from core.testing.module_registry import module_registry_scope
import pytest
error = {'RuntimeError': RuntimeError, 'KeyboardInterrupt': KeyboardInterrupt, 'none': None}[sys.argv[3]]
state, stage, after = sys.argv[4], sys.argv[5], sys.argv[6] == 'True'
if stage.startswith('control-'):
    _, outcome, count = stage.split('-')
    with pytest.MonkeyPatch.context() as patch:
        native.test_selected_registry_slots_restore_without_clearing_foreign_entries(state, outcome, int(count), patch)
    assert not denied_calls, denied_calls
    print('FOREIGN_IMPORT_WORKER_OK')
    sys.exit(0)
failure = error('owned foreign import lifecycle fault') if error else None
workers, fired = [], []
borrowed_table, borrowed_threads = sys.modules, native.threading
class Owner(pytest.MonkeyPatch):
    def __init__(self):
        super().__init__()
        self.target = None
        self.entered, self.release = threading.Event(), threading.Event()
        self.publications = []
    def setitem(self, mapping, name, value):
        if mapping is sys.modules and name == self.target:
            self.publications.append(value)
            self.entered.set()
            assert self.release.wait(10), 'owned module publication was not released'
        return super().setitem(mapping, name, value)
class Worker(threading.Thread):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.errors = inspect.getclosurevars(kwargs['target']).nonlocals['errors']
        workers.append(self)
    def start(self):
        if stage == 'start' and not after:
            fired.append(True)
            raise failure
        super().start()
        if stage == 'start':
            assert publisher_owner.entered.wait(5)
            fired.append(True)
            raise failure
    def join(self, timeout=None):
        selected = stage == 'join' and not fired
        if selected and not after:
            assert publisher_owner.entered.wait(5)
            fired.append(True)
            raise failure
        publisher_owner.release.set()
        result = super().join(timeout=timeout)
        if selected:
            fired.append(True)
            raise failure
        return result
thread_view = ModuleType('threading')
vars(thread_view).update(vars(threading))
thread_view.Thread = Worker
view = module_function_view(native, bindings={'threading': thread_view, '_owned_publish': native._ForeignImport.publish})
assert view._owned_publish.__code__ is native._ForeignImport.publish.__code__
with pytest.MonkeyPatch.context() as prior_owner:
    publisher_owner = Owner()
    subject = native._ForeignImport(publisher_owner)
    expected = native._prior(prior_owner, subject.name, state)
    alias = subject.name + '_loader'
    prior_owner.setitem(sys.modules, alias, None)
    publisher_owner.target = subject.name
    try:
        try:
            with module_registry_scope(alias) as modules:
                modules[alias] = ModuleType(alias)
                view._owned_publish(subject)
        except BaseException as caught:
            assert failure is not None and caught is failure
        else:
            assert failure is None
        assert fired == ([True] if failure else [])
        assert sys.modules[alias] is None
        assert len(workers) == 1 and not workers[0].is_alive() and not workers[0].errors
        started = workers[0].ident is not None
        assert publisher_owner.publications == ([subject.module] if started else [])
        if started:
            subject.assert_live()
        else:
            native._assert_prior({subject.name: expected})
            assert subject.module is None
    finally:
        publisher_owner.release.set()
        for worker in workers:
            if worker.ident is not None:
                threading.Thread.join(worker, timeout=5)
                assert not worker.is_alive()
        publisher_owner.undo()
    native._assert_prior({subject.name: expected})
    assert sys.modules[alias] is None
assert subject.name not in sys.modules and alias not in sys.modules
assert sys.modules is borrowed_table and native.threading is borrowed_threads
assert not denied_calls, denied_calls
print('FOREIGN_IMPORT_WORKER_OK')

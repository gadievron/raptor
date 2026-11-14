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
import json
import pytest
from core.sandbox.tests import test_summary as native
from core.sandbox import summary
from core.testing.sandbox_state_scope import isolated_summary_state, SUMMARY_DEFAULTS, SUMMARY_REGISTRIES
from core.testing.state_isolation import pin_user_state_dirs
from core.testing.module_views import module_function_view
error_name, mode, stage, after_text = sys.argv[3:7]
after = after_text == 'True'
error = {'RuntimeError': RuntimeError, 'KeyboardInterrupt': KeyboardInterrupt, 'none': None}[error_name]
failure = error('owned summary caller fault') if error else None
expected = 4 if mode == 'state' else 8
workers, fired, run_errors, evidence_objects = [], [], [], []
entered, all_entered, release = threading.Event(), threading.Event(), threading.Event()
staged, staged_lock = set(), threading.Lock()
main_ident = threading.get_ident()
operation = 'set_active_run_dir' if mode == 'state' else 'record_denial'
actual_operation = getattr(summary, operation)
def gated_operation(*args, **kwargs):
    result = actual_operation(*args, **kwargs)
    ident = threading.get_ident()
    first = False
    if ident != main_ident:
        with staged_lock:
            if ident not in staged:
                staged.add(ident)
                entered.set()
                first = True
                if len(staged) == expected:
                    all_entered.set()
    if first:
        assert release.wait(10), 'owned summary operation not released'
    return result
class Worker(threading.Thread):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        workers.append(self)
    def run(self):
        try:
            super().run()
        except BaseException as caught:
            run_errors.append(caught)
    def start(self):
        selected = stage == 'start' and not fired
        if selected and not after:
            fired.append(True)
            raise failure
        super().start()
        if selected:
            assert entered.wait(5)
            fired.append(True)
            raise failure
    def join(self, timeout=None):
        selected = stage == 'join' and not fired
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
original = (native.TestThreadSafety.test_concurrent_set_clear_is_serialised if mode == 'state' else native.TestThreadSafety.test_concurrent_record_denial_doesnt_lose_records)
view = module_function_view(native, bindings={'threading': thread_view, '_owned_native': original})
assert view._owned_native.__code__ is original.__code__
borrowed = {key: getattr(summary, key) for key in (*SUMMARY_DEFAULTS, *SUMMARY_REGISTRIES, '_evidence')}
with pytest.MonkeyPatch.context() as state_patch:
    pin_user_state_dirs(state_patch, scratch)
    with isolated_summary_state():
        with pytest.MonkeyPatch.context() as operation_patch:
            base = summary._evidence.EvidenceFile
            class TrackedEvidence(base):
                def __init__(self, *args, **kwargs):
                    super().__init__(*args, **kwargs)
                    evidence_objects.append(self)
            operation_patch.setattr(summary._evidence, 'EvidenceFile', TrackedEvidence)
            operation_patch.setattr(summary, operation, gated_operation)
            try:
                try:
                    view._owned_native(native.TestThreadSafety(), scratch)
                except BaseException as caught:
                    assert failure is not None and caught is failure
                else:
                    assert failure is None
                assert fired == ([True] if failure else [])
                assert len(workers) == expected
                assert not any(worker.is_alive() for worker in workers)
            finally:
                release.set()
                for worker in workers:
                    if worker.ident is not None:
                        threading.Thread.join(worker, timeout=5)
                        assert not worker.is_alive()
                assert not run_errors, run_errors
                started = sum(worker.ident is not None for worker in workers)
                assert len(staged) == started
                if mode == 'denials':
                    path = native._denials_path(scratch)
                    records = [json.loads(line) for line in path.read_text().splitlines() if line] if path.exists() else []
                    assert len(records) == started * 25
                    assert {r['cmd'] for r in records} == {f'cmd-t{tid}-{i}' for tid in range(started) for i in range(25)}
                    assert all(r['returncode'] == 1 and r['type'] == 'network' for r in records)
                else:
                    assert summary.get_active_run_dir() is None
            assert getattr(summary, operation) is gated_operation
    assert all(handle._closed and handle._fd_released for handle in evidence_objects)
assert all(getattr(summary, key) is value for key, value in borrowed.items())
assert getattr(summary, operation) is actual_operation
assert not denied_calls, denied_calls
print('SUMMARY_THREAD_WORKER_OK')

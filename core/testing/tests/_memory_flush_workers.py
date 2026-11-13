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
# Load only the storage leaf, never autonomous's campaign/provider initializer.
import ast
import importlib.util
spec = importlib.util.spec_from_file_location('owned_fuzzing_memory', root / 'packages/autonomous/memory.py')
memory = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = memory
spec.loader.exec_module(memory)
error = {'RuntimeError': RuntimeError, 'KeyboardInterrupt': KeyboardInterrupt, 'none': None}[sys.argv[3]]
position, after, stage = int(sys.argv[4]), sys.argv[5] == 'True', sys.argv[6]
failure = error('owned memory writer lifecycle fault') if error else None
fired = []
release, ready = threading.Event(), threading.Event()
workers, completed = [], []
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
def importer(name, globals=None, locals=None, fromlist=(), level=0):
    if name == 'threading' and level == 0:
        return view
    return builtins.__import__(name, globals, locals, fromlist, level)
native = ModuleType('owned_memory_test')
vars(native).update(Path=Path, FuzzingMemory=memory.FuzzingMemory, FuzzingKnowledge=memory.FuzzingKnowledge)
native.__dict__['__builtins__'] = dict(vars(builtins), __import__=importer)
source = root / 'packages/autonomous/tests/test_memory.py'
tree = ast.parse(source.read_text(), filename=str(source))
nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in {'_k', 'test_parallel_flush_threads_keep_all_entries'}]
assert len(nodes) == 2 and all(not n.decorator_list for n in nodes)
exec(compile(ast.Module(body=nodes, type_ignores=[]), str(source), 'exec'), vars(native))
try:
    try:
        native.test_parallel_flush_threads_keep_all_entries(scratch)
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
started = [worker for worker in workers if worker.ident is not None]
assert len(completed) == len(started)
loaded = memory.FuzzingMemory(memory_file=scratch / 'fuzzing_memory.json')
for tag in ('a', 'b')[:len(started)]:
    for index in range(10):
        assert loaded.recall('strategy', f'{tag}_{index}') is not None
print('MEMORY_FLUSH_WORKER_OK')

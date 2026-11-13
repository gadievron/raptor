import builtins
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
from core.build.tests import test_detection_walk_reads as native
from core.build import build_detector
from core.source import contained
import core.source as source_api
from core.testing.module_views import module_function_view
mode = sys.argv[4]
error = {'RuntimeError': RuntimeError, 'KeyboardInterrupt': KeyboardInterrupt, 'none': None}[sys.argv[3]]
stage, after = sys.argv[5], sys.argv[6] == 'True'
failure = error('owned detection FIFO lifecycle fault') if error else None
blocking = stage == 'start' and after
fired, peers, peer_closed, peer_sentinels = [], [], [], []
repo = scratch / 'a' / 'b' / 'c' / 'repo'
repo.mkdir(parents=True)
fifo = repo / ('a.c' if mode == 'header' else 'CMakeLists.txt')
entered = threading.Event()
workers, reader_fds, closed, sentinels, violations = [], [], [], [], []
os_view = ModuleType('os')
vars(os_view).update(vars(os))
def blocking_open(path, flags, *args, **kwargs):
    if Path(path) != fifo:
        return os.open(path, flags, *args, **kwargs)
    assert flags & os.O_NONBLOCK and flags & os.O_NOFOLLOW
    entered.set()
    fd = os.open(path, flags & ~os.O_NONBLOCK if blocking else flags, *args, **kwargs)
    stamp = os.fstat(fd)
    reader_fds.append((fd, stamp.st_dev, stamp.st_ino))
    return fd
def close_reader(fd):
    if reader_fds and fd == reader_fds[0][0]:
        if closed:
            violations.append('stale FIFO descriptor close')
            raise AssertionError(violations[-1])
        stamp = os.fstat(fd)
        assert (stamp.st_dev, stamp.st_ino) == reader_fds[0][1:]
        os.close(fd)
        closed.append(fd)
        sentinel = os.open(scratch / 'reader-sentinel', os.O_RDWR | os.O_CREAT, 0o600)
        stamp = os.fstat(sentinel)
        sentinels.append((sentinel, stamp.st_dev, stamp.st_ino))
    else:
        os.close(fd)
os_view.open, os_view.close = blocking_open, close_reader
reader = module_function_view(contained, bindings={'os': os_view})
source_view = ModuleType(source_api.__name__)
vars(source_view).update(vars(source_api))
source_view.read_text_capped = reader.read_text_capped
def method_import(name, globals=None, locals=None, fromlist=(), level=0):
    if level == 0 and name == 'core.source' and tuple(fromlist) == ('read_text_capped',):
        return source_view
    return builtins.__import__(name, globals, locals, fromlist, level)
method_view = module_function_view(build_detector, bindings={'_owned_scan': build_detector.BuildDetector.detect_missing_config_headers, '_owned_root': build_detector.BuildDetector._is_cmake_project_root}, import_hook=method_import)
class Detector(build_detector.BuildDetector):
    detect_missing_config_headers = method_view._owned_scan
    _is_cmake_project_root = staticmethod(method_view._owned_root)
assert Detector.detect_missing_config_headers.__code__ is build_detector.BuildDetector.detect_missing_config_headers.__code__
assert Detector._is_cmake_project_root.__code__ is build_detector.BuildDetector._is_cmake_project_root.__code__
class Worker(threading.Thread):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.result = inspect.getclosurevars(kwargs['target']).nonlocals['result']
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
            fired.append(True)
            raise failure
        result = super().join(timeout=timeout)
        if selected:
            fired.append(True)
            raise failure
        return result
thread_view = ModuleType('threading')
vars(thread_view).update(vars(threading))
thread_view.Thread = Worker
peer_view = ModuleType('os')
vars(peer_view).update(vars(os))
def open_peer(path, flags):
    assert Path(path) == fifo and flags == os.O_WRONLY | os.O_NONBLOCK
    fd = os.open(path, flags)
    stamp = os.fstat(fd)
    peers.append((fd, stamp.st_dev, stamp.st_ino))
    return fd
def close_peer(fd):
    assert len(peers) == 1 and fd == peers[0][0]
    assert not workers[0].is_alive() and len(closed) == 1
    stamp = os.fstat(fd)
    assert (stamp.st_dev, stamp.st_ino) == peers[0][1:] == reader_fds[0][1:]
    peer_closed.append(fd)
    assert len(peer_closed) == 1
    os.close(fd)
    sentinel = os.open(scratch / 'peer-sentinel', os.O_RDWR | os.O_CREAT, 0o600)
    stamp = os.fstat(sentinel)
    peer_sentinels.append((sentinel, stamp.st_dev, stamp.st_ino))
peer_view.open, peer_view.close = open_peer, close_peer
original = (native.TestMissingConfigHeaderScanReads.test_fifo_source_does_not_block_the_scan if mode == 'header'
            else native.TestCMakeProjectRootReads.test_fifo_cmakelists_does_not_block)
owner = module_function_view(native, bindings={'BuildDetector': Detector, 'threading': thread_view, 'os': peer_view, '_owned_case': original})
assert owner._owned_case.__code__ is original.__code__
try:
    try:
        case = native.TestMissingConfigHeaderScanReads() if mode == 'header' else native.TestCMakeProjectRootReads()
        owner._owned_case(case, repo)
    except BaseException as caught:
        assert failure is not None and caught is failure
    else:
        assert failure is None
    assert fired == ([True] if failure else [])
    assert len(workers) == 1 and not workers[0].is_alive()
    started = workers[0].ident is not None
    assert len(reader_fds) == len(closed) == int(started) and not violations
    if mode == 'header':
        assert [[(name, path.name) for name, path in value] for value in workers[0].result] == ([[('foo_config.h', 'b.c')]] if started else [])
    else:
        assert workers[0].result == ([False] if started else [])
    assert len(peers) == len(peer_closed)
    assert len(peers) == 1 if blocking else len(peers) <= 1
    if mode == 'cmake' and stage == 'normal':
        regular = scratch / 'regular'
        regular.mkdir()
        native.TestCMakeProjectRootReads().test_real_project_root_still_detected(regular)
finally:
    rescue = None
    if workers and workers[0].is_alive():
        rescue = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
    try:
        for worker in workers:
            if worker.ident is not None:
                threading.Thread.join(worker, timeout=15)
                assert not worker.is_alive()
    finally:
        if rescue is not None:
            os.close(rescue)
        try:
            for fd, dev, ino in sentinels + peer_sentinels:
                stamp = os.fstat(fd)
                assert (stamp.st_dev, stamp.st_ino) == (dev, ino)
        finally:
            for fd, _, _ in sentinels + peer_sentinels:
                os.close(fd)
assert not denied_calls, denied_calls
print('DETECTION_FIFO_WORKER_OK')

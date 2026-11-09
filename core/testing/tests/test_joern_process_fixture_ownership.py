"""Joern's native process fixtures own leaders, survivors and streams."""

import ast
from contextlib import contextmanager, ExitStack, suppress
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
from types import ModuleType

import pytest

from core.testing.processes import reap_on_exit


ROOT = Path(__file__).resolve().parents[3]
CASES = [
    "packages/joern/tests/test_stop_group_escalation.py",
    "packages/joern/tests/test_server_stop_fast.py",
]
pytestmark = [pytest.mark.slow, pytest.mark.skipif(sys.platform != "linux", reason="native Linux process ownership")]


def _native(path):
    names = {"_reap_all", "_reap_member", "_spawn_dead_leader_with_survivor", "_pid_gone",
             "_IGNORING_MEMBER_SRC", "_DYING_LEADER_SRC"}
    nodes = []
    for node in ast.parse((ROOT / path).read_text()).body:
        if getattr(node, "name", None) in names:
            node.decorator_list = []
            nodes.append(node)
        elif isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in names for t in node.targets):
            nodes.append(node)
    namespace = dict(ExitStack=ExitStack, suppress=suppress, os=os, select=select,
                     signal=signal, subprocess=subprocess, sys=sys, reap_on_exit=reap_on_exit)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), path, "exec"), namespace)
    return namespace


def _start():
    return subprocess.Popen(
        [sys.executable, "-c", "import time; print('ready', flush=True); time.sleep(300)"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True,
    )


def _finish(generator, finish):
    if finish == "resume":
        with pytest.raises(StopIteration):
            next(generator)
    elif finish == "close":
        generator.close()
    else:
        error = RuntimeError if finish == "error" else KeyboardInterrupt
        with pytest.raises(error, match="body interrupted"):
            generator.throw(error("body interrupted"))


@pytest.mark.parametrize("path", CASES)
@pytest.mark.parametrize("finish", ["resume", "close", "error", "interrupt"])
def test_native_fixture_reaps_real_leader_and_closes_streams(path, finish):
    namespace = _native(path)
    generator = namespace["_reap_all"]()
    cleanup = next(generator)
    process = _start()
    try:
        cleanup.enter_context(reap_on_exit(process, process_group=True))
        assert select.select([process.stdout], [], [], 5)[0]
        assert process.stdout.readline().strip() == "ready"
        _finish(generator, finish)
        assert process.returncode is not None
        assert process.stdout.closed and process.stderr.closed
    finally:
        generator.close()
        with reap_on_exit(process, process_group=True):
            pass


@pytest.mark.parametrize("finish", ["resume", "close", "error", "interrupt"])
def test_native_fixture_owns_survivor_after_leader_reaped(finish):
    namespace = _native(CASES[0])
    generator = namespace["_reap_all"]()
    cleanup = next(generator)
    try:
        leader, member = namespace["_spawn_dead_leader_with_survivor"](cleanup)
        assert leader.returncode == 0
        assert not namespace["_pid_gone"](member)
        member_fd = os.pidfd_open(member)
        try:
            _finish(generator, finish)
            assert select.select([member_fd], [], [], 5)[0]
            assert leader.stdout.closed
        finally:
            with suppress(ProcessLookupError):
                signal.pidfd_send_signal(member_fd, signal.SIGKILL)
            os.close(member_fd)
    finally:
        generator.close()


@pytest.mark.parametrize("path", CASES)
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_cleanup_error_still_reaps_other_owned_children(path, error):
    namespace = _native(path)
    generator = namespace["_reap_all"]()
    cleanup = next(generator)
    processes = []

    @contextmanager
    def failing_reaper(process):
        try:
            with reap_on_exit(process, process_group=True):
                yield process
        finally:
            raise error("cleanup interrupted")

    try:
        first = _start()
        processes.append(first)
        cleanup.enter_context(reap_on_exit(first, process_group=True))
        second = _start()
        processes.append(second)
        cleanup.enter_context(failing_reaper(second))
        with pytest.raises(error, match="cleanup interrupted"):
            generator.close()
        for process in processes:
            assert process.returncode is not None
            assert process.stdout.closed and process.stderr.closed
    finally:
        generator.close()
        for process in processes:
            with reap_on_exit(process, process_group=True):
                pass


@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_member_signal_error_still_closes_owned_pidfd(error):
    namespace = _native(CASES[0])
    signal_view = ModuleType("signal")
    signal_view.__dict__.update(vars(signal))
    signalled = []

    def interrupted_send(fd, sig):
        signal.pidfd_send_signal(fd, sig)
        signalled.append(fd)
        raise error("member signal interrupted")

    signal_view.pidfd_send_signal = interrupted_send
    namespace["signal"] = signal_view
    generator = namespace["_reap_all"]()
    cleanup = next(generator)
    try:
        leader, member = namespace["_spawn_dead_leader_with_survivor"](cleanup)
        member_fd = os.pidfd_open(member)
        try:
            with pytest.raises(error, match="member signal interrupted"):
                generator.close()
            assert select.select([member_fd], [], [], 5)[0]
            assert leader.stdout.closed
            assert len(signalled) == 1
            with pytest.raises(OSError):
                os.fstat(signalled[0])
        finally:
            with suppress(ProcessLookupError):
                signal.pidfd_send_signal(member_fd, signal.SIGKILL)
            os.close(member_fd)
    finally:
        generator.close()


@pytest.mark.parametrize("fault", ["read_error", "read_interrupt", "invalid_pid", "pidfd_error"])
def test_survivor_startup_failure_still_cleans_private_group(fault):
    namespace = _native(CASES[0])
    process_view = ModuleType("subprocess")
    process_view.__dict__.update(vars(subprocess))
    os_view = ModuleType("os")
    os_view.__dict__.update(vars(os))
    members, leaders = [], []

    class Reader:
        def __init__(self, stream):
            self.stream = stream

        def readline(self):
            line = self.stream.readline()
            members.append(os.pidfd_open(int(line)))
            if fault == "read_error":
                raise RuntimeError("read interrupted")
            if fault == "read_interrupt":
                raise KeyboardInterrupt("read interrupted")
            return "invalid pid" if fault == "invalid_pid" else line

        def close(self):
            self.stream.close()

        @property
        def closed(self):
            return self.stream.closed

    def spawn(*args, **kwargs):
        process = subprocess.Popen(*args, **kwargs)
        leaders.append(process)
        process.stdout = Reader(process.stdout)
        return process

    def no_pidfd(pid):
        raise OSError("pidfd acquisition interrupted")

    process_view.Popen = spawn
    if fault == "pidfd_error":
        os_view.pidfd_open = no_pidfd
    namespace.update(subprocess=process_view, os=os_view)
    generator = namespace["_reap_all"]()
    cleanup = next(generator)
    error = {"read_error": RuntimeError, "read_interrupt": KeyboardInterrupt,
             "invalid_pid": ValueError, "pidfd_error": OSError}[fault]
    try:
        with pytest.raises(error):
            namespace["_spawn_dead_leader_with_survivor"](cleanup)
        generator.close()
        assert len(leaders) == len(members) == 1
        assert leaders[0].returncode is not None
        assert leaders[0].stdout.closed
        assert select.select(members, [], [], 5)[0] == members
    finally:
        generator.close()
        for fd in members:
            with suppress(ProcessLookupError):
                signal.pidfd_send_signal(fd, signal.SIGKILL)
            os.close(fd)
        for leader in leaders:
            with reap_on_exit(leader, process_group=True):
                pass

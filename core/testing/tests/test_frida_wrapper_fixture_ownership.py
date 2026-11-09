"""Real wrapper stubs release detached groups on every owner exit."""

from contextlib import contextmanager, nullcontext
from importlib import import_module
from pathlib import Path
import os
import shutil
import subprocess
from types import ModuleType

import pytest


pytestmark = [pytest.mark.slow, pytest.mark.skipif(os.name != "posix", reason="POSIX wrapper ownership")]
WRAPPERS = ["raptor-frida", "raptor-frida-patch-verify"]
ROUTES = ["plain", pytest.param("setsid", marks=pytest.mark.skipif(shutil.which("setsid") is None, reason="setsid unavailable"))]


@pytest.fixture
def native(monkeypatch):
    module = import_module("core.run.tests.test_frida_wrapper_signals")
    pairs = []
    original = module.pipe_streams

    @contextmanager
    def recorded_pipes():
        with original() as pair:
            pairs.append(pair)
            yield pair

    monkeypatch.setattr(module, "pipe_streams", recorded_pipes)
    yield module, pairs
    assert all(stream.closed for pair in pairs for stream in pair)


def _stub(module, tmp_path):
    child = tmp_path / "stub.pid"
    grandchild = tmp_path / "grandchild.pid"
    env = module._stub_python(tmp_path, (
        "trap 'exit 0' TERM\n"
        f'echo $$ > "{child}"\n'
        "sleep 300 &\n"
        f'echo $! > "{grandchild}"\n'
        "wait\n"
    ))
    stub = tmp_path / "stub-bin" / "python3"
    return stub, env, child, grandchild


def _body(module, owner, stage, finish, paths):
    if stage == "ready":
        assert module._wait_for(lambda: all(module._read_pid(p) is not None for p in paths))
        assert all(module._pid_alive(module._read_pid(p)) for p in paths)
    if finish == "close":
        owner.gen.close()
    elif finish == "error":
        raise RuntimeError("body interrupted")
    elif finish == "interrupt":
        raise KeyboardInterrupt("body interrupted")


def _expected(finish):
    if finish == "error":
        return pytest.raises(RuntimeError, match="body interrupted")
    if finish == "interrupt":
        return pytest.raises(KeyboardInterrupt, match="body interrupted")
    return nullcontext()


def _assert_tree_dead(module, paths):
    pids = [module._read_pid(path) for path in paths]
    assert all(pid is not None for pid in pids)
    # Pipe EOF observes descriptor release, which can precede the final
    # process-state transition after SIGKILL. Use the native liveness wait.
    assert module._wait_for(lambda: not any(module._pid_alive(pid) for pid in pids)), {
        pid: module._proc_state(pid) for pid in pids
    }


@pytest.mark.parametrize("wrapper", WRAPPERS)
@pytest.mark.parametrize("stage", ["startup", "ready"])
@pytest.mark.parametrize("finish", ["resume", "close", "error", "interrupt"])
def test_real_wrapper_owner_cleans_stub_tree(native, tmp_path, wrapper, stage, finish):
    module, pairs = native
    root = module._make_fake_tree(tmp_path, wrapper)
    stub, env, child, grandchild = _stub(module, tmp_path)
    original = stub.read_bytes()
    if wrapper == "raptor-frida":
        args = ["--target", "someprocess", "--template", "syscalls"]
    else:
        before = tmp_path / "before.bin"
        before.write_bytes(b"\x7fELF")
        args = ["--before", str(before)]
    owner = module._owned_wrapper(
        ["bash", str(root / "libexec" / wrapper), *args], stub=stub,
        env=env, cwd=tmp_path, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    with _expected(finish):
        with owner as process:
            _body(module, owner, stage, finish, (child, grandchild))
    assert process.returncode is not None
    assert stub.read_bytes() == original
    assert all(stream.closed for pair in pairs for stream in pair)
    if stage == "ready":
        _assert_tree_dead(module, (child, grandchild))


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("stage", ["startup", "ready"])
@pytest.mark.parametrize("finish", ["resume", "close", "error", "interrupt"])
def test_owner_cleans_inherited_and_detached_groups(native, tmp_path, route, stage, finish):
    module, pairs = native
    stub, env, child, grandchild = _stub(module, tmp_path)
    original = stub.read_bytes()
    args = ["sh", str(stub)]
    if route == "setsid":
        args.insert(0, "setsid")
    owner = module._owned_wrapper(args, stub=stub, env=env, cwd=tmp_path)
    with _expected(finish):
        with owner as process:
            _body(module, owner, stage, finish, (child, grandchild))
    assert process.returncode is not None
    assert stub.read_bytes() == original
    assert all(stream.closed for pair in pairs for stream in pair)
    if stage == "ready":
        _assert_tree_dead(module, (child, grandchild))


@pytest.mark.parametrize("stage", ["second_pipe", "spawn"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_setup_failure_restores_stub_and_closes_pipes(native, tmp_path, monkeypatch, stage, error):
    module, pairs = native
    stub, env, _, _ = _stub(module, tmp_path)
    original = stub.read_bytes()
    pipes = module.pipe_streams
    calls = 0

    @contextmanager
    def failing_pipe():
        nonlocal calls
        calls += 1
        with pipes() as pair:
            if calls == 2:
                raise error("setup interrupted")
            yield pair

    process_view = ModuleType("subprocess")
    process_view.__dict__.update(vars(subprocess))

    def no_spawn(*args, **kwargs):
        raise error("setup interrupted")

    if stage == "second_pipe":
        monkeypatch.setattr(module, "pipe_streams", failing_pipe)
    else:
        process_view.Popen = no_spawn
        monkeypatch.setattr(module, "subprocess", process_view)
    with pytest.raises(error, match="setup interrupted"):
        with module._owned_wrapper(["sh", str(stub)], stub=stub, env=env):
            pytest.fail("body reached after setup failure")
    assert stub.read_bytes() == original
    assert all(stream.closed for pair in pairs for stream in pair)


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_stub_write_failure_restores_partial_write(native, tmp_path, error):
    module, pairs = native
    stub, env, _, _ = _stub(module, tmp_path)
    original = stub.read_bytes()
    writes = 0

    class WriteFaultPath(type(Path())):
        def write_text(self, *args, **kwargs):
            nonlocal writes
            result = super().write_text(*args, **kwargs)
            writes += 1
            if writes == 1:
                raise error("stub write interrupted")
            return result

    with pytest.raises(error, match="stub write interrupted"):
        with module._owned_wrapper(["sh", str(stub)], stub=WriteFaultPath(stub), env=env):
            pytest.fail("body reached after failed stub write")
    assert stub.read_bytes() == original
    assert all(stream.closed for pair in pairs for stream in pair)


@pytest.mark.parametrize("fault", ["lifeline_close", "reaper_exit"])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_cleanup_error_still_releases_stub_tree(native, tmp_path, monkeypatch, fault, error):
    module, pairs = native
    stub, env, child, grandchild = _stub(module, tmp_path)
    original = stub.read_bytes()
    pipes, reaper = module.pipe_streams, module.reap_on_exit
    calls = 0

    class CloseFault:
        def __init__(self, writer):
            self.writer = writer
            self.closed_once = False

        def fileno(self):
            return self.writer.fileno()

        def close(self):
            self.writer.close()
            if not self.closed_once:
                self.closed_once = True
                raise error("cleanup interrupted")

    @contextmanager
    def faulting_pipes():
        nonlocal calls
        calls += 1
        with pipes() as (reader, writer):
            yield reader, CloseFault(writer) if calls == 1 else writer

    @contextmanager
    def faulting_reaper(process, **kwargs):
        try:
            with reaper(process, **kwargs):
                yield process
        finally:
            raise error("cleanup interrupted")

    monkeypatch.setattr(module, "pipe_streams" if fault == "lifeline_close" else "reap_on_exit",
                        faulting_pipes if fault == "lifeline_close" else faulting_reaper)
    with pytest.raises(error, match="cleanup interrupted"):
        with module._owned_wrapper(["sh", str(stub)], stub=stub, env=env) as process:
            assert module._wait_for(lambda: module._read_pid(grandchild) is not None)
    assert process.returncode is not None
    _assert_tree_dead(module, (child, grandchild))
    assert stub.read_bytes() == original
    assert all(stream.closed for pair in pairs for stream in pair)

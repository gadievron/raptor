"""High-FD fixtures cannot overwrite pre-existing slots or strand replacements."""

import ast
import os
import resource
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


class DescriptorTable:
    """An inert fd table keeps old fixed-destination tests safe to exercise."""

    def __init__(self, error, fault):
        self.error, self.fault = error, fault
        self.original = {300: "existing-300", 5000: "existing-5000"}
        self.fds = dict(self.original)
        self.flags = {}
        self.limit = self.prior = (1024, 8192)
        self.duplicated = None
        self.next_fd = 100
        self.backend_calls = []

    def fail(self, stage):
        if self.fault == stage:
            raise self.error(f"injected {stage} failure")

    def allocate(self, value):
        while self.next_fd in self.fds:
            self.next_fd += 1
        fd = self.next_fd
        self.fds[fd] = value
        self.next_fd += 1
        return fd

    def pipe(self):
        self.fail("pipe")
        return self.allocate("pipe-r"), self.allocate("pipe-w")

    def open(self, *args):
        self.fail("open")
        return self.allocate("planted")

    def dup2(self, source, target, inheritable=True):
        self.fail("duplicate")
        self.fds[target] = self.fds[source]
        self.duplicated = target
        self.set_inheritable(target, inheritable)
        return target

    def duplicate(self, source, operation, minimum):
        self.fail("duplicate")
        fd = minimum
        while fd in self.fds:
            fd += 1
        self.fds[fd] = self.fds[source]
        self.duplicated = fd
        return fd

    def set_inheritable(self, fd, value):
        self.fail("inherit")
        self.flags[fd] = value

    def close(self, fd):
        if fd not in self.fds:
            raise OSError("modeled descriptor already closed")
        del self.fds[fd]

    def exists(self, path):
        if str(path).startswith("/proc/self/fd/"):
            return int(str(path).rsplit("/", 1)[1]) in self.fds
        return os.path.exists(path)

    def setrlimit(self, which, value):
        self.limit = value
        if value != self.prior:
            self.fail("limit")

    def backend(self, argv, **kwargs):
        self.backend_calls.append(argv)
        calls = [
            node
            for node in ast.walk(ast.parse(argv[-1]))
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "fstat"
        ]
        assert (
            len(calls) == 1 and ast.literal_eval(calls[0].args[0]) == self.duplicated
        ), "probe did not follow the allocated descriptor"
        assert self.flags[self.duplicated] is True
        self.fail("backend")
        return subprocess.CompletedProcess(argv, 0, "FD-CLOSED", "")

    def os_proxy(self):
        return SimpleNamespace(
            **(
                vars(os)
                | {
                    "pipe": self.pipe,
                    "open": self.open,
                    "dup2": self.dup2,
                    "close": self.close,
                    "set_inheritable": self.set_inheritable,
                    "path": SimpleNamespace(
                        **(vars(os.path) | {"exists": self.exists})
                    ),
                }
            )
        )


_MODEL_CASES = [
    ("spawn", fault)
    for fault in ("limit", "pipe", "duplicate", "inherit", "directory", "backend")
]
_MODEL_CASES += [
    ("audit", fault) for fault in ("open", "duplicate", "inherit", "backend")
]


@pytest.mark.parametrize("kind,fault", _MODEL_CASES)
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_high_fd_fixture_failure_preserves_existing_slots(
    kind, fault, error, tmp_path, monkeypatch
):
    _exercise_modeled_fixture(kind, fault, error, tmp_path, monkeypatch)


@pytest.mark.parametrize("kind", ["spawn", "audit"])
def test_high_fd_fixture_success_preserves_existing_slots(kind, tmp_path, monkeypatch):
    _exercise_modeled_fixture(kind, "none", OSError, tmp_path, monkeypatch)


def _exercise_modeled_fixture(kind, fault, error, tmp_path, monkeypatch):
    from core.sandbox.tests import test_spawn_lifecycle_hardening as spawn
    from core.sandbox.tests import test_landlock_audit_fd_sweep as audit
    from core.sandbox import _spawn

    module = spawn if kind == "spawn" else audit
    table = DescriptorTable(error, fault)
    output = tmp_path / "owned-output"

    def directory(*args, **kwargs):
        table.fail("directory")
        output.mkdir()
        return str(output)

    with monkeypatch.context() as patcher:
        patcher.setattr(module, "os", table.os_proxy())
        patcher.setattr(
            module,
            "fcntl",
            SimpleNamespace(F_DUPFD=0, fcntl=table.duplicate),
            raising=False,
        )
        patcher.setattr(resource, "getrlimit", lambda _: table.limit)
        patcher.setattr(resource, "setrlimit", table.setrlimit)
        if kind == "spawn":
            patcher.setattr(module, "tempfile", SimpleNamespace(mkdtemp=directory))
            patcher.setattr(_spawn, "run_sandboxed", table.backend)
            case = module.TestHighFdSweep(
                "test_inheritable_fd_above_lowered_limit_is_closed"
            )
            invoke = case.test_inheritable_fd_above_lowered_limit_is_closed
        else:
            patcher.setattr(module, "_ptrace_ready", lambda: True)
            patcher.setattr(module.mod, "run_landlock_audit", table.backend)
            case = None
            invoke = lambda: (
                module.test_high_noncloexec_fd_does_not_survive_into_the_target(
                    tmp_path
                )
            )
        try:
            if fault == "none":
                invoke()
            else:
                with pytest.raises(error, match=f"injected {fault} failure"):
                    invoke()
        finally:
            if case is not None:
                assert case.doCleanups(), "modeled unittest cleanup failed"
    assert table.fds == table.original, (
        "fixture overwrote an existing slot or leaked its own descriptors"
    )
    assert table.limit == table.prior, "fixture failed to restore the descriptor limit"
    assert not output.exists()


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_host_replacement_is_owned_before_old_descriptor_close(error, monkeypatch):
    from core.sandbox.tests import test_host_response_reliability as module

    table = DescriptorTable(error, "none")
    old = table.allocate("reply-r")
    writer = table.allocate("request-w")
    host = SimpleNamespace(_read_fd=old, _write_fd=writer)

    def close_host():
        for fd in (host._read_fd, host._write_fd):
            if fd in table.fds:
                table.close(fd)

    host.close = close_host

    def close(fd):
        table.close(fd)
        if fd == old:
            raise error("injected old-reader close failure")

    limits = SimpleNamespace(
        RLIMIT_NOFILE=resource.RLIMIT_NOFILE,
        RLIM_INFINITY=resource.RLIM_INFINITY,
        getrlimit=lambda _: table.limit,
        setrlimit=table.setrlimit,
    )
    with monkeypatch.context() as patcher:
        patcher.setattr(module, "os", SimpleNamespace(**(vars(os) | {"close": close})))
        patcher.setattr(
            module, "fcntl", SimpleNamespace(F_DUPFD=0, fcntl=table.duplicate)
        )
        patcher.setattr(module, "resource", limits)
        patcher.setattr(module, "fake_host", lambda *args: (host, None, []))
        with pytest.raises(error, match="injected old-reader close failure"):
            module.test_high_numbered_reply_descriptor_is_supported()
    assert table.fds == table.original, (
        "replacement reply descriptor was never owned by the host"
    )
    assert table.limit == table.prior


@pytest.mark.parametrize("fault", ["socket", "timeout", "old-close"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_parser_socket_replacement_setup_reclaims_both_handles(
    fault, error, monkeypatch
):
    from core.sandbox.tests import test_parser_jail_io_reliability as module

    table = DescriptorTable(error, "none")

    class Socket:
        def __init__(self, fd, original=False):
            self.fd, self.original = fd, original

        def fileno(self):
            return self.fd

        def settimeout(self, value):
            if fault == "timeout":
                raise error("injected replacement setup failure")

        def close(self):
            if self.fd in table.fds:
                table.close(self.fd)
            if self.original and fault == "old-close":
                raise error("injected replacement setup failure")

    old = Socket(table.allocate("parser-parent"), original=True)
    jail = SimpleNamespace(
        _sock=old, start=lambda: None, stop=lambda: jail._sock.close()
    )

    def adopt(*args, fileno):
        if fault == "socket":
            raise error("injected replacement setup failure")
        return Socket(fileno)

    with monkeypatch.context() as patcher:
        patcher.setattr(module.jail_mod, "ParserJail", lambda: jail)
        patcher.setattr(module, "os", table.os_proxy(), raising=False)
        patcher.setattr(module, "socket", SimpleNamespace(socket=adopt))
        patcher.setattr(
            module, "fcntl", SimpleNamespace(F_DUPFD=0, fcntl=table.duplicate)
        )
        patcher.setattr(
            module,
            "resource",
            SimpleNamespace(
                RLIMIT_NOFILE=resource.RLIMIT_NOFILE,
                RLIM_INFINITY=resource.RLIM_INFINITY,
                getrlimit=lambda _: table.limit,
                setrlimit=table.setrlimit,
            ),
        )
        with pytest.raises(error, match="injected replacement setup failure"):
            module.test_high_descriptor_worker_still_parses(patcher)
    assert table.fds == table.original, "parser replacement setup stranded a descriptor"
    assert table.limit == table.prior


@pytest.mark.slow
@pytest.mark.skipif(sys.platform != "linux", reason="owned private-child fd proof")
def test_native_audit_fixture_preserves_an_occupied_slot(tmp_path):
    # A fresh audit-stack import can exceed the fast-tier budget under load.
    root = str(Path(__file__).resolve().parents[3])
    code = """import ast,fcntl,os,subprocess,sys
from contextlib import suppress
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from core.sandbox.tests import test_landlock_audit_fd_sweep as module
root=Path(sys.argv[2])
source=os.open(root/'sentinel',os.O_CREAT|os.O_RDWR,0o600)
occupied=fcntl.fcntl(source,fcntl.F_DUPFD,300)
try:
    if occupied!=300:
        sys.exit(77)
    identity=os.fstat(occupied)
    module._ptrace_ready=lambda:True
    def backend(argv,**kwargs):
        calls=[n for n in ast.walk(ast.parse(argv[-1])) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='fstat']
        assert len(calls)==1
        planted=ast.literal_eval(calls[0].args[0])
        assert os.get_inheritable(planted)
        return subprocess.CompletedProcess(argv,0,'FD-CLOSED','')
    module.mod.run_landlock_audit=backend
    module.test_high_noncloexec_fd_does_not_survive_into_the_target(root)
    after=os.fstat(occupied)
    assert (after.st_dev,after.st_ino)==(identity.st_dev,identity.st_ino)
    os.write(occupied,b'kept')
finally:
    with suppress(OSError):os.close(occupied)
    os.close(source)
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", code, root, str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode == 77:
        pytest.skip("private child could not reserve descriptor 300")
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "sentinel").read_bytes() == b"kept"

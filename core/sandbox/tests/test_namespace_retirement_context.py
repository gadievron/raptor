"""Parent collection cleanup with owned pipes and inert process/native seams."""

import contextlib
import io
import os
import socket
import subprocess
from types import SimpleNamespace

import pytest

from core.sandbox import _spawn
from core.testing.module_views import module_function_view


def _exercise(scratch, *, ambient, cancel, body_error, scope=False):
    owned = set()
    pairs = []
    events = []
    death = set()
    token = 7654321
    cancellation = KeyboardInterrupt("owned parent retirement")
    root = scratch / "stub"
    endpoints = []

    def pipe():
        pair = os.pipe()
        owned.update(pair)
        pairs.append(pair)
        events.append("pipe")
        return pair

    def check(fd):
        assert fd in owned, ("unowned descriptor", fd)

    def close(fd):
        check(fd)
        owned.remove(fd)
        os.close(fd)

    def read(fd, size):
        check(fd)
        return os.read(fd, size)

    def write(fd, data):
        check(fd)
        return os.write(fd, data)

    def blocking(fd, value):
        check(fd)
        os.set_blocking(fd, value)

    def inheritable(fd):
        check(fd)
        return os.get_inheritable(fd)

    def death_pipe():
        pair = pipe()
        death.add(pair[1])
        return pair

    def death_close(fd):
        if fd not in death:
            return False
        death.remove(fd)
        close(fd)
        assert events[-1] in ("wait-success", "wait-error")
        events.append("death-retired")
        if cancel and not scope:
            raise cancellation
        return True

    def fork():
        assert len(pairs) == 4 and events.count("fork") == 0
        events.append("fork")
        write(pairs[0][1], b"R")
        write(pairs[2][1], b"G:")
        # The fake child needs no process; retain only its go reader.
        duplicate = os.dup(pairs[1][0])
        owned.add(duplicate)
        return token

    def waitpid(pid, flags):
        assert (pid, flags) == (token, 0)
        assert events.count("mapping") == 2
        if body_error is not None:
            events.append("wait-error")
            raise body_error
        events.append("wait-success")
        return token, 0

    def mapping(pid, helper, lines):
        assert pid == token and helper in ("inert-newuidmap", "inert-newgidmap")
        assert lines == ["0", "1234", "1"]
        events.append("mapping")

    def mkdir(**kwargs):
        assert kwargs == {"prefix": ".raptor-sbx-"}
        root.mkdir(mode=0o700)
        return str(root)

    def rmdir(path):
        assert path == str(root)
        root.rmdir()
        events.append("stub-retired")

    def environment(path, mode):
        assert (path, mode) == ("/proc/self/environ", "rb")
        return io.BytesIO(b"OWNED_TEST_NAME=value\0")

    def forbidden(*args, **kwargs):
        raise AssertionError("unreviewed process/native/helper route")

    class Endpoint:
        def __init__(self, raw, *, parent):
            self.raw = raw
            self.parent = parent

        def shutdown(self, how):
            assert self.parent and how == socket.SHUT_RDWR
            self.raw.shutdown(how)

        def close(self):
            self.raw.close()
            if self.parent:
                assert events[-1] == "death-retired"
                events.append("scope-retired")
                if cancel:
                    raise cancellation

    def socketpair():
        raw_pair = socket.socketpair()
        endpoints.extend(raw_pair)
        return Endpoint(raw_pair[0], parent=True), Endpoint(raw_pair[1], parent=False)

    def receiver_thread(**kwargs):
        assert kwargs["daemon"] and kwargs["name"].startswith("unix-scope-recv-")
        # The owned endpoint lifecycle is exercised without a notify receiver.
        return SimpleNamespace(start=lambda: None)

    imports = {
        (0, "tempfile"): SimpleNamespace(mkdtemp=mkdir),
        (1, "landlock"): SimpleNamespace(check_landlock_available=forbidden),
        (0, "core.config"): SimpleNamespace(RaptorConfig=SimpleNamespace(TARGET_ENV_STRIP_SET=(), LLM_API_KEY_VARS=())),
        (0, "core.security.credential_env"): SimpleNamespace(
            CREDENTIAL_BEARING_ENV_VARS=(), is_credential_shaped=lambda name: False,
            is_model_traffic_redirect_shaped=lambda name: False),
        (0, "ctypes"): SimpleNamespace(CDLL=lambda *a, **kw: SimpleNamespace(prctl=forbidden)),
        (0, "ctypes.util"): SimpleNamespace(find_library=lambda name: "inert-libc"),
        (0, "core.sandbox._proxy_bridge"): SimpleNamespace(_bring_up_loopback=forbidden),
        (1, "_unix_scope"): SimpleNamespace(probe_unix_scope=lambda: True),
    }

    def import_local(name, globals=None, locals=None, fromlist=(), level=0):
        key = (level, name)
        assert key in imports, ("unreviewed import", key)
        return imports[key]

    private_os = SimpleNamespace(
        pipe=pipe, read=read, write=write, close=close,
        get_inheritable=inheritable, set_blocking=blocking,
        fork=fork, waitpid=waitpid, getuid=lambda: 1234, getgid=lambda: 1234,
        rmdir=rmdir, WIFEXITED=os.WIFEXITED, WEXITSTATUS=os.WEXITSTATUS,
        WIFSIGNALED=os.WIFSIGNALED, WTERMSIG=os.WTERMSIG,
    )
    view = module_function_view(_spawn, bindings={
        "os": private_os, "open": environment,
        "open_death_pipe": death_pipe, "close_death_w": death_close,
        "_DEATH_W_LOCK": contextlib.nullcontext(),
        "_pidns_proc_mount_expectation": lambda skip: False,
        "_find_sandbox_binary": lambda name: "inert-" + name,
        "_gidmap_allow_available": lambda: None, "_run_newuidmap": mapping,
        "_readable_fds": lambda fds, timeout: [fd for fd in fds if fd in owned],
        "_kill_and_reap": forbidden, "_teardown_target": forbidden,
        "_make_landlock_preexec": forbidden,
        "_make_seccomp_preexec": (lambda *args, **kwargs: forbidden) if scope else forbidden,
        "_reap_tracer": forbidden,
        "shutil": SimpleNamespace(rmtree=forbidden),
        "_socket_mod": SimpleNamespace(socketpair=socketpair, SHUT_RDWR=socket.SHUT_RDWR),
        "threading": SimpleNamespace(Thread=receiver_thread),
        "_drop_host_tmpdir_grants": lambda grants, *args: grants,
        "_anchor_grants_to_bind_view": lambda grants, *args, **kwargs: (grants, []),
        "_pin_bind_sources": lambda *args, **kwargs: {},
        # Only value construction is available, never a subprocess launcher.
        "subprocess": SimpleNamespace(PIPE=-1, CompletedProcess=subprocess.CompletedProcess),
    }, import_hook=import_local)
    def invoke():
        return view.run_sandboxed(
            ["INERT-NOT-EXECUTED"], target=str(scratch) if scope else None, output=None,
            block_network=True, nproc_limit=0, limits={}, writable_paths=[],
            readable_paths=None, allowed_tcp_ports=None, seccomp_profile="full" if scope else None,
            seccomp_block_udp=False, env={}, cwd=None, timeout=None,
            capture_output=False,
        )

    def caller():
        if not ambient:
            return invoke()
        try:
            raise LookupError("unrelated caller exception")
        except LookupError:
            return invoke()

    try:
        caught = None
        result = None
        try:
            result = caller()
        except BaseException as error:
            caught = error
        expected = body_error if body_error is not None else cancellation if cancel else None
        assert caught is expected
        if body_error is not None and cancel:
            assert "parent owner cleanup: KeyboardInterrupt" in body_error.__notes__
        if expected is None:
            assert result.returncode == 0 and result._setup_status is None
        final_events = ["death-retired", "scope-retired", "stub-retired"] if scope else ["death-retired", "stub-retired"]
        assert events[-len(final_events):] == final_events
        assert not root.exists() and not death
        # Only the harness-owned duplicate go reader remains.
        assert len(owned) == 1
        assert all(endpoint.fileno() == -1 for endpoint in endpoints)
    finally:
        for endpoint in endpoints:
            endpoint.close()
        for fd in tuple(owned):
            close(fd)
        if root.exists():
            root.rmdir()


@pytest.mark.parametrize("ambient", [False, True])
@pytest.mark.parametrize("cancel", [False, True])
def test_parent_collection_retirement_uses_local_context(tmp_path, ambient, cancel):
    _exercise(tmp_path, ambient=ambient, cancel=cancel, body_error=None)


@pytest.mark.parametrize("ambient", [False, True])
def test_parent_collection_error_survives_cleanup_cancellation(tmp_path, ambient):
    _exercise(tmp_path, ambient=ambient, cancel=True, body_error=OSError("owned wait failure"))


@pytest.mark.parametrize("ambient", [False, True])
@pytest.mark.parametrize("cancel", [False, True])
def test_parent_scope_retirement_reports_its_own_failure(tmp_path, ambient, cancel):
    _exercise(tmp_path, ambient=ambient, cancel=cancel, body_error=None, scope=True)


@pytest.mark.parametrize("ambient", [False, True])
def test_parent_collection_error_survives_scope_cancellation(tmp_path, ambient):
    _exercise(tmp_path, ambient=ambient, cancel=True, body_error=OSError("owned wait failure"), scope=True)

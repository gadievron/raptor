"""Strict prerequisite ownership with private transports and real descriptors."""

import builtins
from contextlib import contextmanager
import os
from pathlib import Path
import shutil
import sys
from types import SimpleNamespace

import pytest

from core.sandbox import context, proxy, landlock, seccomp, state, preflight, probes
from core.sandbox.errors import SandboxSetupError
from core.sandbox.tests.test_context_decision_pins import _FakeProxy
from core.testing.module_views import module_function_view


@pytest.mark.skipif(sys.platform != "linux", reason="Linux strict prerequisite ownership")
@pytest.mark.parametrize("backend,cleanup_error", [
    ("tcp", None), ("tcp", RuntimeError), ("tcp", KeyboardInterrupt),
    ("unix", None), ("unix", RuntimeError), ("unix", KeyboardInterrupt),
    ("none", None), ("healthy", None),
])
def test_strict_refusal_retires_previously_bound_proxy_lane(tmp_path, backend, cleanup_error):
    owned, calls, directories, errors = {}, [], {}, []
    secondary = cleanup_error("owned transport close failure") if cleanup_error else None

    def acquire():
        for fd in os.pipe():
            info = os.fstat(fd)
            owned[fd] = (info.st_dev, info.st_ino)

    def close():
        for fd in owned:
            os.close(fd)
        if secondary is not None:
            raise secondary

    class Proxy(_FakeProxy):
        def bind_tcp_lane(self, **kwargs):
            calls.append("bind-tcp")
            acquire()
            return 18081

        def close_tcp_lane(self, port):
            assert port == 18081
            calls.append("close-tcp")
            close()

        def bind_unix(self, path, **kwargs):
            calls.append("bind-unix")
            parent = Path(path).parent
            info = parent.stat()
            directories[parent] = (info.st_dev, info.st_ino)
            acquire()

        def unbind_unix(self, path):
            assert Path(path).parent in directories
            calls.append("close-unix")
            close()

    instance = Proxy()
    modules = {
        "proxy": module_function_view(proxy, bindings={"get_proxy": lambda *a, **kw: instance}),
        "landlock": module_function_view(landlock, bindings={
            "check_landlock_available": lambda: True, "_get_landlock_abi": lambda: 8,
        }),
        "seccomp": module_function_view(seccomp, bindings={
            "check_seccomp_available": lambda: backend != "unix",
        }),
        "probes": module_function_view(probes, bindings={
            "mount_unavailable_reason": lambda: ("owned namespace unavailable", "owned instruction"),
            "check_unshare_engages": lambda flags: (True, ""),
        }),
    }

    def imports(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 1 and name in modules:
            return modules[name]
        if level == 1 and not name and any(n in modules for n in fromlist):
            return SimpleNamespace(**{n: modules[n] for n in fromlist if n in modules})
        return builtins.__import__(name, globals, locals, fromlist, level)

    preflight_view = module_function_view(preflight, import_hook=imports)
    actual_preflight = preflight_view.strict_backend_error

    def capture_error(**kwargs):
        error = actual_preflight(**kwargs)
        if error is not None:
            errors.append(error)
        return error

    preflight_view.strict_backend_error = capture_error
    modules["preflight"] = preflight_view
    private = module_function_view(context, bindings={
        "sandbox": context.sandbox.__wrapped__,
        "check_net_available": lambda: backend in ("unix", "healthy"),
        "check_mount_available": lambda: backend in ("unix", "healthy"),
        "check_seatbelt_available": lambda: False, "_make_preexec_fn": lambda *a, **kw: None,
        "_landlock": modules["landlock"], "_seccomp": modules["seccomp"],
        "state": module_function_view(state, bindings={"warn_once": lambda name: False}),
    }, import_hook=imports)

    def invoke():
        with contextmanager(private.sandbox)(output=str(tmp_path), profile="strict",
                                             use_egress_proxy=backend != "none",
                                             proxy_hosts=["allowed.example"]):
            calls.append("yield")

    try:
        if backend == "healthy":
            invoke()
        else:
            with pytest.raises(SandboxSetupError, match="strict") as caught:
                invoke()
            assert errors and caught.value is errors[0]
            assert "yield" not in calls
            if secondary is not None:
                assert any(cleanup_error.__name__ in note for note in caught.value.__notes__)
        if backend == "none":
            assert calls == [] and not owned
        else:
            lane = "tcp" if backend == "tcp" else "unix"
            assert calls == [f"bind-{lane}", *(["yield"] if backend == "healthy" else []), f"close-{lane}"]
            assert len(owned) == 2
            for fd in owned:
                with pytest.raises(OSError):
                    os.fstat(fd)
        assert all(not p.exists() for p in directories)
    finally:
        for fd, identity in owned.items():
            try:
                info = os.fstat(fd)
            except OSError:
                continue
            if (info.st_dev, info.st_ino) == identity:
                os.close(fd)
        for path, identity in directories.items():
            if path.is_dir() and not path.is_symlink():
                info = path.stat()
                if (info.st_dev, info.st_ino) == identity:
                    shutil.rmtree(path)

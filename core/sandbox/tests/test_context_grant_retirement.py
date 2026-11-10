"""Held grant ownership on a private namespace-retry route; no target launch."""

import builtins
from contextlib import contextmanager
import os
import subprocess
import sys
from types import SimpleNamespace

import pytest

from core.sandbox import context, _spawn, _pathpin, landlock, probes, seccomp, state, proxy
from core.testing.module_views import module_function_view
from core.sandbox.tests.test_context_decision_pins import _FakeProxy


@pytest.mark.skipif(sys.platform != "linux", reason="Linux O_PATH grant owner")
@pytest.mark.parametrize("failure_type,operation_failure", [
    (None, False), (KeyboardInterrupt, False), (MemoryError, False),
    (KeyboardInterrupt, True),
])
def test_pin_close_interruption_does_not_skip_sibling_pins(tmp_path, failure_type, operation_failure):
    readable = tmp_path / "readable"
    readable.mkdir()
    owned, closes, dispatches = {}, [], []
    registered, retired = [], []

    class Proxy(_FakeProxy):
        def register_sandbox(self, **kwargs):
            token = len(registered) + 1
            registered.append(token)
            return token

        def unregister_sandbox(self, token):
            retired.append(token)
            return []

    proxy_instance = Proxy()
    proxy_view = module_function_view(proxy, bindings={"get_proxy": lambda *a, **kw: proxy_instance})
    failure = failure_type("owned grant close after effect") if failure_type else None
    original = ValueError("owned retry failure")

    def pin(path):
        fd = _pathpin.open_pinned(path)
        info = os.fstat(fd)
        owned[fd] = (info.st_dev, info.st_ino)
        return fd

    def close(fd):
        os.close(fd)
        if fd in owned:
            closes.append(fd)
            if len(closes) == 1 and failure is not None:
                raise failure

    def execute(cmd, **kwargs):
        dispatches.append(kwargs)
        if len(dispatches) == 2 and operation_failure:
            raise original
        result = subprocess.CompletedProcess(cmd, 0, b"", b"")
        result._setup_status = ("X", "owned exec setup failure") if len(dispatches) == 1 else None
        return result

    spawn = module_function_view(_spawn, bindings={
        "run_sandboxed": execute, "mount_ns_available": lambda: True,
    })
    pathpin = module_function_view(_pathpin, bindings={"open_pinned": pin})
    ll = module_function_view(landlock, bindings={
        "check_landlock_available": lambda: True, "_get_landlock_abi": lambda: 8,
    })
    sc = module_function_view(seccomp, bindings={"check_seccomp_available": lambda: True})
    probe = module_function_view(probes, bindings={"check_unshare_engages": lambda flags: (True, "")})

    def imports(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 1:
            modules = {"_spawn": spawn, "_pathpin": pathpin, "landlock": ll,
                       "seccomp": sc, "probes": probe, "proxy": proxy_view}
            if name in modules:
                return modules[name]
            if not name and any(n in modules for n in fromlist):
                return SimpleNamespace(**{n: modules[n] for n in fromlist if n in modules})
        return builtins.__import__(name, globals, locals, fromlist, level)

    private = module_function_view(context, bindings={
        "sandbox": context.sandbox.__wrapped__,
        "state": module_function_view(state, bindings={
            "_speculative_failure_cache": {}, "warn_once": lambda name: False,
        }),
        "check_net_available": lambda: True,
        "check_mount_available": lambda: True,
        "check_seatbelt_available": lambda: False,
        "_make_preexec_fn": lambda *a, **kw: None,
        "os": module_function_view(os, bindings={"close": close}),
    }, import_hook=imports)
    try:
        def invoke():
            with contextmanager(private.sandbox)(target=str(tmp_path), restrict_reads=True,
                                                 readable_paths=[str(readable)], use_egress_proxy=True,
                                                 proxy_hosts=["allowed.example"]) as run:
                return run(["/bin/true"], capture_output=True, timeout=60)

        expected = original if operation_failure else failure
        if expected is None:
            assert invoke().returncode == 0
        else:
            with pytest.raises(type(expected)) as caught:
                invoke()
            assert caught.value is expected
        assert len(dispatches) == 2
        assert registered and retired == registered
        assert len(owned) >= 2
        assert closes == list(owned)
        for fd in owned:
            with pytest.raises(OSError):
                os.fstat(fd)
    finally:
        for fd, identity in owned.items():
            try:
                info = os.fstat(fd)
            except OSError:
                continue
            if (info.st_dev, info.st_ino) == identity:
                os.close(fd)

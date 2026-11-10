"""Context exit controls with private proxy state and real owned descriptors."""

import builtins
from contextlib import contextmanager
import os
import sys
from types import SimpleNamespace

import pytest

from core.sandbox import context, proxy, landlock, seccomp, state
from core.sandbox.tests.test_context_decision_pins import _FakeProxy
from core.testing.module_views import module_function_view


@pytest.mark.skipif(sys.platform != "linux", reason="Linux parent proxy routing")
@pytest.mark.parametrize("stage,body_error", [
    ("normal", False), ("drain", False), ("audit-before", False),
    ("audit-after", False), ("lane", False), ("drain", True), ("audit-after", True),
])
def test_context_exit_attempts_sibling_owners(tmp_path, stage, body_error):
    calls, owned = [], {}
    failure = KeyboardInterrupt("owned context cleanup interruption")
    original = ValueError("owned context body failure")

    class Proxy(_FakeProxy):
        active = False

        def bind_tcp_lane(self, **kwargs):
            for fd in os.pipe():
                info = os.fstat(fd)
                owned[fd] = (info.st_dev, info.st_ino)
            return 18081

        def register_sandbox(self, **kwargs):
            calls.append("register")
            return 1

        def unregister_sandbox(self, token):
            assert token == 1
            calls.append("unregister")
            if stage == "drain":
                raise failure
            return []

        def set_lane_audit(self, key, value):
            calls.append("audit-on" if value else "audit-off")
            if not value and stage == "audit-before":
                raise failure
            self.active = value
            if not value and stage == "audit-after":
                raise failure
            return True

        def close_tcp_lane(self, port):
            assert port == 18081
            calls.append("close-lane")
            for fd in owned:
                os.close(fd)
            if stage == "lane":
                raise failure

    instance = Proxy()
    modules = {
        "proxy": module_function_view(proxy, bindings={"get_proxy": lambda *a, **kw: instance}),
        "landlock": module_function_view(landlock, bindings={
            "check_landlock_available": lambda: True, "_get_landlock_abi": lambda: 8,
        }),
        "seccomp": module_function_view(seccomp, bindings={"check_seccomp_available": lambda: True}),
    }

    def imports(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 1 and name in modules:
            return modules[name]
        if level == 1 and not name and any(n in modules for n in fromlist):
            return SimpleNamespace(**{n: modules[n] for n in fromlist if n in modules})
        return builtins.__import__(name, globals, locals, fromlist, level)

    private = module_function_view(context, bindings={
        "sandbox": context.sandbox.__wrapped__, "check_net_available": lambda: False,
        "check_seatbelt_available": lambda: False, "_make_preexec_fn": lambda *a, **kw: None,
        "_landlock": modules["landlock"], "_seccomp": modules["seccomp"],
        "state": module_function_view(state, bindings={"warn_once": lambda name: False}),
    }, import_hook=imports)
    try:
        def invoke():
            with contextmanager(private.sandbox)(output=str(tmp_path), use_egress_proxy=True,
                                                 proxy_hosts=["allowed.example"], audit=True):
                calls.append("yield")
                if body_error:
                    raise original

        if stage == "normal":
            invoke()
        else:
            expected = original if body_error else failure
            with pytest.raises(type(expected)) as caught:
                invoke()
            assert caught.value is expected
        assert calls == ["register", "audit-on", "yield", "unregister", "audit-off", "close-lane"]
        # A setter failing before effect cannot be claimed cleared. The
        # error remains visible while sibling ownership is retired.
        assert instance.active == (stage == "audit-before")
        assert len(owned) == 2
        for fd in owned:
            with pytest.raises(OSError):
                os.fstat(fd)
    finally:
        instance.active = False
        for fd, identity in owned.items():
            try:
                info = os.fstat(fd)
            except OSError:
                continue
            if (info.st_dev, info.st_ino) == identity:
                os.close(fd)

"""Context entry ownership with a private proxy; no sockets or target launch."""

import builtins
from contextlib import contextmanager
import sys
from types import SimpleNamespace

import pytest

from core.sandbox import context, proxy, landlock, seccomp, state
from core.sandbox.tests.test_context_decision_pins import _FakeProxy
from core.testing.module_views import module_function_view


@pytest.mark.skipif(sys.platform != "linux", reason="Linux proxy lane routing")
@pytest.mark.parametrize("stage,error_type", [
    ("normal", None), ("register", RuntimeError), ("body", ValueError),
    ("enable-before", RuntimeError), ("enable-after", RuntimeError),
    ("enable-before", KeyboardInterrupt), ("enable-after", KeyboardInterrupt),
])
def test_audit_setup_error_retires_context_owners(tmp_path, stage, error_type):
    calls = []
    failure = error_type("owned entry failure") if error_type else None

    class Proxy(_FakeProxy):
        active = False

        def register_sandbox(self, **kwargs):
            calls.append("register")
            if stage == "register":
                raise failure
            return 1

        def unregister_sandbox(self, token):
            assert token == 1
            calls.append("unregister")
            return []

        def set_lane_audit(self, key, value):
            calls.append("audit-on" if value else "audit-off")
            if value and stage == "enable-before":
                raise failure
            self.active = value
            if value and stage == "enable-after":
                raise failure
            return True

        def close_tcp_lane(self, port):
            assert port == 18081
            calls.append("close-lane")

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

    def invoke():
        with contextmanager(private.sandbox)(output=str(tmp_path), use_egress_proxy=True,
                                             proxy_hosts=["allowed.example"], audit=True):
            calls.append("yield")
            if stage == "body":
                raise failure

    try:
        if failure is not None:
            with pytest.raises(type(failure)) as caught:
                invoke()
            assert caught.value is failure
        else:
            invoke()
        if stage == "register":
            assert calls == ["register", "close-lane"]
        else:
            assert calls.count("unregister") == 1
            assert calls.index("unregister") < calls.index("audit-off") < calls.index("close-lane")
            assert ("yield" in calls) == (stage in ("normal", "body"))
        assert calls.count("close-lane") == 1
        assert not instance.active
    finally:
        instance.active = False

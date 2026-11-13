"""Private imports and startup faults for the fake-server fixture companion."""

import builtins
from contextlib import contextmanager
from types import ModuleType, SimpleNamespace
import threading
import pytest
from core.audit import binary_context as producer
from core.audit.tests import test_binary_context as native
from core.testing.module_views import module_function_view

@contextmanager
def exercise(phase, tmp_path):
    threads, gates, callbacks = [], [], []
    real = threading.Thread
    patch = pytest.MonkeyPatch()
    entered = threading.Event()
    error = KeyboardInterrupt if "interrupt" in phase else RuntimeError
    det = ModuleType("packages.ghidra.detect")
    det.pyghidra_available = lambda: False
    srv = ModuleType("packages.ghidra.server")
    srv.GhidraServer = None
    exit_view = SimpleNamespace(register=lambda callback: callbacks.append(callback))
    def producer_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "packages.ghidra.detect":
            return det
        if name == "packages.ghidra.server":
            return srv
        if name == "atexit":
            return exit_view
        return builtins.__import__(name, globals, locals, fromlist, level)
    class Cache(dict):
        def pop(self, *args):
            assert not any(thread.is_alive() for thread in threads)
            return super().pop(*args)
    bc = module_function_view(producer, bindings={"_SERVER_CACHE": Cache(), "_SERVER_BOOT_LOCKS": Cache(), "_SERVER_CACHE_LOCK": threading.Lock()}, import_hook=producer_import)
    borrowed = (producer._SERVER_CACHE, producer._SERVER_BOOT_LOCKS, producer._project_for_binary)
    class Gate(threading.Event):
        def __init__(self):
            super().__init__()
            gates.append(self)
        def wait(self, timeout=None):
            entered.set()
            return super().wait(timeout)
    class Thread(real):
        def __init__(self, *args, **kwargs):
            self.joins = []
            self.index = len(threads)
            super().__init__(*args, **kwargs)
            threads.append(self)
        def start(self):
            if self.index == 0 and phase.startswith("before-"):
                raise error("owned start failure")
            super().start()
            if self.index == 0 and phase.startswith("after-"):
                assert entered.wait(2), "actual FakeServer.start gate not reached"
                raise error("owned start failure")
        def join(self, *args, **kwargs):
            self.joins.append((args, kwargs))
            assert det.pyghidra_available()
            assert srv.GhidraServer is not None
            return super().join(*args, **kwargs)
    namespace = ModuleType("threading")
    vars(namespace).update(vars(threading))
    namespace.Thread, namespace.Event = Thread, Gate
    core_root = SimpleNamespace(audit=SimpleNamespace(binary_context=bc))
    packages_root = SimpleNamespace(ghidra=SimpleNamespace(detect=det, server=srv))
    def native_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "threading":
            return namespace
        if name == "core.audit.binary_context":
            return core_root
        if name in {"packages.ghidra.detect", "packages.ghidra.server"}:
            return packages_root
        return builtins.__import__(name, globals, locals, fromlist, level)
    function = native.TestServerBootSingleFlight.test_concurrent_first_calls_boot_once
    view = module_function_view(native, bindings={"_owned_case": function}, import_hook=native_import)
    assert view._owned_case.__code__ is function.__code__
    try:
        yield lambda: view._owned_case(native.TestServerBootSingleFlight(), tmp_path, patch), threads, gates, bc, callbacks
    finally:
        try:
            for gate in gates:
                gate.set()
            for thread in threads:
                if thread.ident is not None:
                    real.join(thread, timeout=10)
                    assert not thread.is_alive()
            with bc._SERVER_CACHE_LOCK:
                bc._SERVER_CACHE.pop(str((tmp_path / "app.gpr").resolve()), None)
                bc._SERVER_BOOT_LOCKS.pop(str((tmp_path / "app.gpr").resolve()), None)
        finally:
            patch.undo()
    assert producer._SERVER_CACHE is borrowed[0]
    assert producer._SERVER_BOOT_LOCKS is borrowed[1]
    assert producer._project_for_binary is borrowed[2]
    assert threading.Thread is real

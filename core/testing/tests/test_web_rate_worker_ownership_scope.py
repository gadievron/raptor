import pytest
from contextlib import contextmanager
from types import ModuleType
import threading
import packages.web.tests.test_client_hardening as native
from core.testing.module_views import module_function_view

CASES = {"rate": native.test_rate_limiter_reservation_is_thread_safe}

@contextmanager
def exercise(case, phase):
    real = threading.Thread
    release = threading.Event()
    threads, clients, stops = [], [], []
    error = KeyboardInterrupt if "interrupt" in phase else RuntimeError
    class Client(native.WebClient):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.close_states = []
            clients.append(self)
        def close(self):
            self.close_states.append(tuple(thread.is_alive() for thread in threads))
            return super().close()
    class Thread(real):
        def __init__(self, *args, **kwargs):
            target = kwargs["target"]
            self.native_target = target
            self.client = target.__self__
            assert target.__func__ is native.WebClient._rate_limit_wait
            self.completed = False
            def running(*args, **kwargs):
                assert release.wait(10), "owned worker gate not released"
                result = target(*args, **kwargs)
                self.completed = True
                return result
            kwargs["target"] = running
            self.index, self.joins = len(threads), []
            super().__init__(*args, **kwargs)
            threads.append(self)
        def start(self):
            if self.index == 0 and phase.startswith("before-"):
                raise error("owned start failure")
            if phase == "normal":
                release.set()
            super().start()
            if self.index == 0 and phase.startswith("after-"):
                raise error("owned start failure")
        def join(self, *args, **kwargs):
            self.joins.append((args, kwargs))
            release.set()
            return super().join(*args, **kwargs)
    namespace = ModuleType("threading")
    vars(namespace).update(vars(threading))
    namespace.Thread = Thread
    function = CASES[case]
    view = module_function_view(native, bindings={"_owned_case": function, "threading": namespace, "WebClient": Client})
    assert view._owned_case.__code__ is function.__code__
    try:
        yield view._owned_case, threads, clients
    finally:
        for stop in stops:
            stop.set()
        release.set()
        for thread in threads:
            if thread.ident is not None:
                real.join(thread, timeout=30)
                assert not thread.is_alive()
        for client in clients:
            native.WebClient.close(client)


@pytest.mark.parametrize("phase", ["normal", "before-error", "after-error", "before-interrupt", "after-interrupt"])
def test_real_rate_workers_retire_before_client_close(phase):
    original_thread = threading.Thread
    original_wait = native.WebClient._rate_limit_wait
    with exercise("rate", phase) as (invoke, threads, clients):
        if phase == "normal":
            invoke()
        else:
            error = KeyboardInterrupt if "interrupt" in phase else RuntimeError
            with pytest.raises(error, match="owned start failure"):
                invoke()
        assert len(threads) == 5
        started = [thread for thread in threads if thread.ident is not None]
        expected = 5 if phase == "normal" else (0 if phase.startswith("before-") else 1)
        assert len(started) == expected
        assert all(not thread.is_alive() for thread in threads)
        assert all(thread.completed and thread.joins for thread in started)
        assert all(not thread.completed and not thread.joins for thread in threads if thread.ident is None)
        assert len(clients) == 1
        assert clients[0].close_states
        assert all(not any(state) for state in clients[0].close_states)
        assert all(thread.native_target.__func__ is original_wait for thread in threads)
        assert threading.Thread is original_thread
        assert native.WebClient._rate_limit_wait is original_wait

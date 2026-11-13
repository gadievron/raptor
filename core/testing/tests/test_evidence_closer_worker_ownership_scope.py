from contextlib import contextmanager
from types import ModuleType
import os
import threading
import pytest
import core.sandbox.tests.test_evidence_lifecycle as native
from core.testing.module_views import module_function_view

@contextmanager
def exercise(phase, tmp_path, verdict):
    real_thread = threading.Thread
    real_evidence = native.evidence.EvidenceFile
    borrowed_os = native.evidence.os
    original_write = os.write
    threads, handles = [], []
    error = KeyboardInterrupt if "interrupt" in phase else RuntimeError
    patch = pytest.MonkeyPatch()
    class Handle(real_evidence):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.close_states = []
            handles.append(self)
        def close(self, *args, **kwargs):
            self.close_states.append(tuple(thread.is_alive() for thread in threads))
            return super().close(*args, **kwargs)
    patch.setattr(native.evidence, "EvidenceFile", Handle)
    class Thread(real_thread):
        def __init__(self, *args, **kwargs):
            target = kwargs["target"]
            self.native_target = target
            cells = dict(zip(target.__code__.co_freevars, (c.cell_contents for c in target.__closure__)))
            self.result, self.errors = cells["results"], cells["errors"]
            verify = cells["handle"].verify
            state = dict(zip(verify.__code__.co_freevars, (c.cell_contents for c in verify.__closure__)))
            self.entered, self.release = state["entered"], state["release"]
            self.verifications = state["verifications"]
            close_fd = native.evidence.os.close
            close_state = dict(zip(close_fd.__code__.co_freevars, (c.cell_contents for c in close_fd.__closure__)))
            self.closes = close_state["closes"]
            self.index = len(threads)
            self.completed, self.joins, self.join_writes = False, [], []
            def running(*args, **kwargs):
                result = target(*args, **kwargs)
                self.completed = True
                return result
            kwargs["target"] = running
            super().__init__(*args, **kwargs)
            threads.append(self)
        def start(self):
            if self.index == 0 and phase.startswith("before-"):
                raise error("owned start failure")
            super().start()
            if self.index == 0 and phase.startswith("after-"):
                assert self.entered.wait(5), "actual verifier was not entered"
                raise error("owned start failure")
        def join(self, *args, **kwargs):
            self.joins.append((args, kwargs))
            self.join_writes.append(native.evidence.os.write)
            return super().join(*args, **kwargs)
    namespace = ModuleType("threading")
    vars(namespace).update(vars(threading))
    namespace.Thread = Thread
    function = native.test_concurrent_closers_share_one_verification_and_release
    view = module_function_view(native, bindings={"_owned_case": function, "threading": namespace})
    assert view._owned_case.__code__ is function.__code__
    try:
        yield lambda: view._owned_case(tmp_path, patch, verdict), threads, handles
    finally:
        try:
            for thread in threads:
                thread.release.set()
            for thread in threads:
                if thread.ident is not None:
                    real_thread.join(thread, timeout=5)
                    assert not thread.is_alive()
            for handle in handles:
                real_evidence.close(handle, verify=False)
        finally:
            patch.undo()
    assert native.evidence.EvidenceFile is real_evidence
    assert native.evidence.os is borrowed_os
    assert os.write is original_write


@pytest.mark.parametrize("verdict", [True, False])
@pytest.mark.parametrize("phase", ["normal", "before-error", "after-error", "before-interrupt", "after-interrupt"])
def test_closers_retire_before_final_owner_release(phase, verdict, tmp_path):
    original_thread = threading.Thread
    original_close = os.close
    original_evidence = native.evidence.EvidenceFile
    original_os = native.evidence.os
    with exercise(phase, tmp_path, verdict) as (invoke, threads, handles):
        if phase == "normal":
            invoke()
        else:
            error = KeyboardInterrupt if "interrupt" in phase else RuntimeError
            with pytest.raises(error, match="owned start failure"):
                invoke()
        assert len(threads) == 2 and len(handles) == 1
        first, second = threads
        handle = handles[0]
        started = [thread for thread in threads if thread.ident is not None]
        expected = 2 if phase == "normal" else (0 if phase.startswith("before-") else 1)
        assert len(started) == expected
        assert all(not thread.is_alive() for thread in threads)
        assert all(thread.completed and thread.joins for thread in started)
        assert all(not thread.completed and not thread.joins for thread in threads if thread.ident is None)
        assert first.release.is_set()
        assert not first.errors
        assert first.result == [verdict] * expected
        assert first.verifications == ([True] if expected else [])
        assert first.closes == [handle.fd]
        assert handle.close_states[-1] == (False, False)
        assert handle._closed and handle._fd_released
        assert handle._close_result is (verdict if expected else True)
        assert threading.Thread is original_thread
        assert os.close is original_close
    assert native.evidence.EvidenceFile is original_evidence
    assert native.evidence.os is original_os

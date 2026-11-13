import json
from contextlib import contextmanager
from types import ModuleType
import os
import threading
import pytest
import core.sandbox.tests.test_evidence_append_resync as native
from core.testing.module_views import module_function_view

@contextmanager
def exercise(phase, tmp_path):
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
    class Thread(real_thread):
        def __init__(self, *args, **kwargs):
            target = kwargs["target"]
            self.native_target = target
            cells = dict(zip(target.__code__.co_freevars, (c.cell_contents for c in target.__closure__)))
            self.failed, self.result = cells["failed"], cells["result"]
            self.entered = threading.Event()
            self.completed, self.joins = False, []
            def running(*args, **kwargs):
                self.entered.set()
                result = target(*args, **kwargs)
                self.completed = True
                return result
            kwargs["target"] = running
            super().__init__(*args, **kwargs)
            threads.append(self)
        def start(self):
            if phase.startswith("before-"):
                raise error("owned start failure")
            super().start()
            if phase.startswith("after-"):
                assert self.entered.wait(1), "actual writer callback was not entered"
                raise error("owned start failure")
        def join(self, *args, **kwargs):
            self.joins.append((args, kwargs))
            return super().join(*args, **kwargs)
    threading_view = ModuleType("threading")
    vars(threading_view).update(vars(threading))
    threading_view.Thread = Thread
    evidence_view = ModuleType(native.evidence.__name__)
    vars(evidence_view).update(vars(native.evidence))
    evidence_view.EvidenceFile = Handle
    function = native.test_recovery_state_is_set_before_another_writer_can_enter
    view = module_function_view(native, bindings={"_owned_case": function, "threading": threading_view, "evidence": evidence_view})
    assert view._owned_case.__code__ is function.__code__
    try:
        yield lambda: view._owned_case(tmp_path, patch), threads, handles
    finally:
        try:
            for thread in threads:
                thread.failed.set()
            for thread in threads:
                if thread.ident is not None:
                    real_thread.join(thread, timeout=2)
                    assert not thread.is_alive()
            for handle in handles:
                real_evidence.close(handle)
        finally:
            patch.undo()
    assert native.evidence.EvidenceFile is real_evidence
    assert native.evidence.os is borrowed_os
    assert os.write is original_write


@pytest.mark.parametrize("phase", ["normal", "before-error", "after-error", "before-interrupt", "after-interrupt"])
def test_resync_writer_retires_before_actual_evidence_close(phase, tmp_path):
    original_thread = threading.Thread
    original_write = os.write
    original_evidence = native.evidence.EvidenceFile
    original_os = native.evidence.os
    with exercise(phase, tmp_path) as (invoke, threads, handles):
        if phase == "normal":
            invoke()
        else:
            error = KeyboardInterrupt if "interrupt" in phase else RuntimeError
            with pytest.raises(error, match="owned start failure"):
                invoke()
        assert len(threads) == 1 and len(handles) == 1
        thread, handle = threads[0], handles[0]
        assert not thread.is_alive()
        assert thread.failed.is_set()
        if phase.startswith("before-"):
            assert thread.ident is None
            assert not thread.completed and not thread.joins
            assert not thread.result
            assert handle.path.read_bytes() == b""
        else:
            assert thread.completed and thread.joins
            assert thread.result == [True]
            assert json.loads(handle.path.read_bytes().splitlines()[-1]) == {"second": "preserved"}
        assert handle.close_states == [(False,)]
        assert handle._closed and handle._fd_released
        assert thread.native_target.__code__.co_name == "second_writer"
        assert threading.Thread is original_thread
        assert os.write is original_write
        assert native.evidence.EvidenceFile is original_evidence
    assert native.evidence.os is original_os

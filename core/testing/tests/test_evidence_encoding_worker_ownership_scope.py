from contextlib import contextmanager
from types import ModuleType
import os
import threading
import pytest
import core.sandbox.tests.test_evidence_lifecycle as native
from core.testing.module_views import module_function_view

@contextmanager
def exercise(phase, tmp_path):
    real_thread = threading.Thread
    real_evidence = native.evidence.EvidenceFile
    borrowed_os = native.evidence.os
    original_write = os.write
    threads, handles, victims = [], [], []
    error = KeyboardInterrupt if "interrupt" in phase else RuntimeError
    patch = pytest.MonkeyPatch()
    class Handle(real_evidence):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.close_states = []
            self.victims = victims
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
            encode = cells["PausedLine"].encode
            state = dict(zip(encode.__code__.co_freevars, (c.cell_contents for c in encode.__closure__)))
            self.entered, self.release = state["entered"], state["release"]
            self.completed, self.joins, self.join_writes = False, [], []
            def running(*args, **kwargs):
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
                assert self.entered.wait(5), "actual encoder was not entered"
                raise error("owned start failure")
        def join(self, *args, **kwargs):
            self.joins.append((args, kwargs))
            self.join_writes.append(native.evidence.os.write)
            return super().join(*args, **kwargs)
    namespace = ModuleType("threading")
    vars(namespace).update(vars(threading))
    namespace.Thread = Thread
    os_view = ModuleType("os")
    vars(os_view).update(vars(os))
    def open_victim(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        victims.append({"fd": fd, "closed": False, "close_states": []})
        return fd
    def close_victim(fd):
        owned = next(record for record in victims if record["fd"] == fd and not record["closed"])
        owned["close_states"].append(tuple(thread.is_alive() for thread in threads))
        result = os.close(fd)
        owned["closed"] = True
        return result
    os_view.open, os_view.close = open_victim, close_victim
    function = native.test_close_during_encoding_cannot_write_to_reused_descriptor
    view = module_function_view(native, bindings={"_owned_case": function, "threading": namespace, "os": os_view})
    assert view._owned_case.__code__ is function.__code__
    try:
        yield lambda: view._owned_case(tmp_path, patch), threads, handles
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
            for victim in victims:
                if not victim["closed"]:
                    close_victim(victim["fd"])
        finally:
            patch.undo()
    assert native.evidence.EvidenceFile is real_evidence
    assert native.evidence.os is borrowed_os
    assert os.write is original_write


@pytest.mark.parametrize("phase", ["normal", "before-error", "after-error", "before-interrupt", "after-interrupt"])
def test_encoder_cleanup_preserves_intentional_close_and_owns_descriptors(phase, tmp_path):
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
        assert thread.release.is_set()
        assert not thread.errors
        if phase.startswith("before-"):
            assert thread.ident is None
            assert not thread.completed and not thread.joins
            assert not thread.result
        else:
            assert thread.completed and thread.joins
        if phase == "normal":
            assert thread.result == [False]
            assert handle.close_states == [(True,), (False,)]
            assert (tmp_path / "other-file").read_bytes() == b"unchanged"
            assert len(handle.victims) == 1
            assert handle.victims[0]["closed"]
            assert handle.victims[0]["close_states"] == [(False,)]
            assert any(getattr(write, "__name__", None) == "reused_write" for write in thread.join_writes)
        else:
            assert handle.close_states == [(False,)]
            assert not handle.victims
            assert not (tmp_path / "other-file").exists()
            if phase.startswith("after-"):
                assert thread.result == [True]
                assert handle.path.read_bytes() == b"late record\n"
        assert handle._closed and handle._fd_released
        assert threading.Thread is original_thread
        assert os.write is original_write
    assert native.evidence.EvidenceFile is original_evidence
    assert native.evidence.os is original_os

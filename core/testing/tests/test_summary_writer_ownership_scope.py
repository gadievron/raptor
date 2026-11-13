import json
from contextlib import contextmanager
from types import ModuleType
import threading
import pytest
import core.sandbox.tests.test_summary_run_generation as native
from core.testing.module_views import module_function_view
from core.testing.sandbox_state_scope import SUMMARY_DEFAULTS, SUMMARY_REGISTRIES

@contextmanager
def exercise(phase, tmp_path):
    real = threading.Thread
    threads = []
    error = KeyboardInterrupt if "interrupt" in phase else RuntimeError
    names = (*SUMMARY_DEFAULTS, *SUMMARY_REGISTRIES, "_evidence", "dumps_artifact", "_log_security_event")
    borrowed = {name: getattr(native.summary, name) for name in names}
    borrowed_disabled = native.state._cli_sandbox_disabled
    patch = pytest.MonkeyPatch()
    fixture = native.isolated_state.__wrapped__(patch)
    next(fixture)
    class Thread(real):
        def __init__(self, *args, **kwargs):
            target = kwargs["target"]
            self.native_target = target
            state = dict(zip(target.__code__.co_freevars, (c.cell_contents for c in target.__closure__)))
            self.errors = state["errors"]
            self.serializer = native.summary.dumps_artifact
            cells = dict(zip(self.serializer.__code__.co_freevars, (c.cell_contents for c in self.serializer.__closure__)))
            self.release, self.entered = cells["release"], cells["entered"]
            self.completed, self.joins = False, []
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
                assert self.entered.wait(5), "actual serializer was not reached"
                raise error("owned start failure")
        def join(self, *args, **kwargs):
            self.joins.append((args, kwargs))
            assert native.summary.dumps_artifact is self.serializer
            return super().join(*args, **kwargs)
    namespace = ModuleType("threading")
    vars(namespace).update(vars(threading))
    namespace.Thread = Thread
    function = native.test_threaded_transition_does_not_append_to_new_run_handle
    view = module_function_view(native, bindings={"_owned_case": function, "threading": namespace})
    assert view._owned_case.__code__ is function.__code__
    try:
        yield lambda: view._owned_case(tmp_path, patch), threads
    finally:
        try:
            for thread in threads:
                thread.release.set()
            for thread in threads:
                if thread.ident is not None:
                    real.join(thread, timeout=5)
                    assert not thread.is_alive()
        finally:
            try:
                next(fixture)
            except StopIteration:
                pass
    assert all(getattr(native.summary, name) is value for name, value in borrowed.items())
    assert native.state._cli_sandbox_disabled is borrowed_disabled


@pytest.mark.parametrize("phase", ["normal", "before-error", "after-error", "before-interrupt", "after-interrupt"])
def test_summary_writer_retires_before_native_owner_restores(phase, tmp_path):
    original_thread = threading.Thread
    original_serializer = native.summary.dumps_artifact
    original_evidence = native.summary._evidence
    handle = None
    with exercise(phase, tmp_path) as (invoke, threads):
        if phase == "normal":
            invoke()
        else:
            error = KeyboardInterrupt if "interrupt" in phase else RuntimeError
            with pytest.raises(error, match="owned start failure"):
                invoke()
        assert len(threads) == 1
        thread = threads[0]
        assert not thread.is_alive()
        if phase.startswith("before-"):
            assert thread.ident is None
            assert not thread.completed and not thread.joins
            assert native.summary._denial_count == 0
        else:
            assert thread.completed and thread.joins
            assert native.summary._denial_count == 1
        assert thread.release.is_set()
        assert not thread.errors
        first = tmp_path / "first" / ".audit" / native.summary.DENIALS_FILE
        second = tmp_path / "second" / ".audit" / native.summary.DENIALS_FILE
        if phase == "normal":
            assert not first.exists()
            records = [json.loads(line) for line in second.read_text().splitlines()]
            assert [record["cmd"] for record in records] == ["current command"]
        elif phase.startswith("after-"):
            assert not second.exists()
            records = [json.loads(line) for line in first.read_text().splitlines()]
            assert [record["cmd"] for record in records] == ["stale command"]
        else:
            assert not first.exists() and not second.exists()
        handle = native.summary._evidence_handle
        assert native.summary.dumps_artifact is thread.serializer
        assert threading.Thread is original_thread
    assert native.summary.dumps_artifact is original_serializer
    assert native.summary._evidence is original_evidence
    if handle is not None:
        assert handle._closed and handle._fd_released

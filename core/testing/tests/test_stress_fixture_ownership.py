"""Warm registries and owned mock workers survive native fixture lifetimes."""

import ast
import concurrent.futures
from contextlib import nullcontext
from pathlib import Path
import threading
from types import ModuleType

import pytest

from core.testing.stress_state import isolated_stress_workers
from packages.sca.calibration import stress


ROOT = Path(__file__).resolve().parents[3]
PATHS = ["packages/sca/calibration/tests/" + leaf for leaf in (
    "test_stress_sweep.py", "test_stress_remeasure.py", "test_stress_timeout_retry.py",
)]


def _view(original):
    view = ModuleType(original.__name__)
    view.__dict__.update(vars(original))
    return view


def _stress_view():
    view = _view(stress)
    view._ACTIVE_SCANS = {"PyPI/caller": 17.0}
    view._ACTIVE_SCANS_LOCK = threading.Lock()
    return view


def _native(path, name, namespace):
    node = None
    for candidate in ast.parse((ROOT / path).read_text()).body:
        if isinstance(candidate, (ast.FunctionDef, ast.ClassDef)) and candidate.name == name:
            node = candidate
            break
    assert node is not None, name
    node.decorator_list = []
    exec(compile(ast.Module(body=[node], type_ignores=[]), path, "exec"), namespace)
    return namespace[name]


@pytest.mark.parametrize("path", PATHS)
@pytest.mark.parametrize("finish", ["resume", "close", "interrupt"])
@pytest.mark.parametrize("body_registry", [False, True])
def test_native_registry_scope_drains_before_restoring(path, finish, body_registry):
    view = _stress_view()
    borrowed, lock = view._ACTIVE_SCANS, view._ACTIVE_SCANS_LOCK
    old_concurrent, old_threading = view.concurrent, view.threading
    old_scan = view._scan_one_inner
    patch = pytest.MonkeyPatch()
    fixture = _native(path, "_clean_in_flight_registry", {"stress_mod": view})
    kwargs = {"monkeypatch": patch} if "monkeypatch" in fixture.__code__.co_varnames else {}
    generator = fixture(**kwargs)
    pool = heartbeat = controller = None
    started, release, cleanup_started = (threading.Event() for _ in range(3))
    observed = []
    try:
        next(generator)
        assert view._ACTIVE_SCANS == {}
        assert view._ACTIVE_SCANS is not borrowed
        assert view._ACTIVE_SCANS_LOCK is lock
        if body_registry:
            patch.setattr(view, "_ACTIVE_SCANS", {})
        private = view._ACTIVE_SCANS
        scan = lambda: "fixture scan"
        patch.setattr(view, "_scan_one_inner", scan)
        pool = view.concurrent.futures.ThreadPoolExecutor(max_workers=1)

        def worker():
            with lock:
                view._ACTIVE_SCANS["PyPI/owned"] = 19.0
            started.set()
            assert release.wait(timeout=5), "test worker was never released"
            try:
                return view._scan_one_inner()
            finally:
                with lock:
                    view._ACTIVE_SCANS.pop("PyPI/owned", None)

        future = pool.submit(worker)
        assert started.wait(timeout=5)
        original_shutdown = pool.shutdown

        def shutdown(*args, **kwargs):
            cleanup_started.set()
            return original_shutdown(*args, **kwargs)

        pool.shutdown = shutdown

        def release_during_cleanup():
            if cleanup_started.wait(timeout=5):
                observed.append(view._ACTIVE_SCANS is private and view._scan_one_inner is scan)
            release.set()

        controller = threading.Thread(target=release_during_cleanup)
        controller.start()
        stopped = view.threading.Event()
        heartbeat = view.threading.Thread(target=stopped.wait, daemon=True)
        heartbeat.start()
        if finish == "resume":
            with pytest.raises(StopIteration):
                next(generator)
        elif finish == "interrupt":
            with pytest.raises(KeyboardInterrupt):
                generator.throw(KeyboardInterrupt)
        else:
            generator.close()
        controller.join(timeout=5)
        assert not controller.is_alive()
        assert observed == [True]
        assert future.done() and future.result() == "fixture scan"
        assert not heartbeat.is_alive()
        assert all(not t.is_alive() for t in pool._threads)
        assert view._ACTIVE_SCANS is borrowed
        assert borrowed == {"PyPI/caller": 17.0}
        assert private == {}
        assert view.concurrent is old_concurrent
        assert view.threading is old_threading
        assert view._scan_one_inner is old_scan
        assert view._ACTIVE_SCANS_LOCK is lock
    finally:
        release.set()
        if controller is not None:
            cleanup_started.set()
            controller.join(timeout=5)
        if pool is not None:
            pool.shutdown(wait=True, cancel_futures=True)
        if heartbeat is not None:
            stopped.set()
            heartbeat.join(timeout=5)
        generator.close()
        patch.undo()


@pytest.mark.parametrize("finish", ["normal", "error", "interrupt"])
def test_recording_executor_preserves_borrowed_futures(finish):
    view = _stress_view()
    patch = pytest.MonkeyPatch()
    namespace = {"concurrent": concurrent, "pytest": pytest, "stress_mod": view}
    recording = _native(PATHS[2], "_RecordingExecutor", namespace)
    borrowed = [concurrent.futures.Future()]
    borrowed[0].set_result(stress.StressResult(
        project="caller", ecosystem="PyPI", elapsed_seconds=1.0,
        deps_analysed=1, vuln_findings=0, eco_breakdown={},
    ))
    recording.submitted = borrowed
    fixture = _native(PATHS[2], "recording_executor", namespace)
    class BodyFailure(Exception):
        pass
    error = BodyFailure if finish == "error" else KeyboardInterrupt
    try:
        with pytest.raises(error) if finish != "normal" else nullcontext():
            with isolated_stress_workers(view, patch):
                factory = fixture(patch)
                assert factory.submitted is not borrowed
                pool = factory(max_workers=1)
                future = pool.submit(lambda: "owned")
                assert future.result(timeout=5) == "owned"
                assert factory.submitted == [future]
                if finish != "normal":
                    raise error
        assert recording.submitted is borrowed
        assert borrowed[0].result().project == "caller"
        assert all(not thread.is_alive() for thread in pool._threads)
    finally:
        patch.undo()
        if "pool" in locals():
            pool.shutdown(wait=True, cancel_futures=True)


@pytest.mark.parametrize("fail_at", [1, 2, 3])
def test_partial_scope_publication_restores_borrowed_bindings(monkeypatch, fail_at):
    from contextlib import contextmanager
    from types import FunctionType
    from core.testing import module_state, stress_state

    view = _stress_view()
    before = {name: getattr(view, name) for name in ("_ACTIVE_SCANS", "threading", "concurrent")}
    calls = 0

    class FailingPatch(pytest.MonkeyPatch):
        def setattr(self, *args, **kwargs):
            nonlocal calls
            super().setattr(*args, **kwargs)
            calls += 1
            if calls == fail_at:
                raise RuntimeError("publication interrupted")

    pytest_view = _view(pytest)
    pytest_view.MonkeyPatch = FailingPatch
    raw = module_state.isolated_module_state.__wrapped__
    private = FunctionType(raw.__code__, {**raw.__globals__, "pytest": pytest_view})
    private.__kwdefaults__ = raw.__kwdefaults__
    monkeypatch.setattr(stress_state, "isolated_module_state", contextmanager(private))
    patch = pytest.MonkeyPatch()
    with pytest.raises(RuntimeError, match="publication interrupted"):
        with isolated_stress_workers(view, patch):
            pytest.fail("scope yielded after failed publication")
    for name, original in before.items():
        assert getattr(view, name) is original
    assert before["_ACTIVE_SCANS"] == {"PyPI/caller": 17.0}
    assert not view._ACTIVE_SCANS_LOCK.locked()


@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_thread_start_failure_after_effect_still_joins(error):
    view = _stress_view()
    borrowed = view._ACTIVE_SCANS
    patch = pytest.MonkeyPatch()
    with pytest.raises(error):
        with isolated_stress_workers(view, patch):
            stop = view.threading.Event()
            thread = view.threading.Thread(target=stop.wait, daemon=True)
            start = thread.start

            def failed_start():
                start()
                raise error

            thread.start = failed_start
            thread.start()
    assert not thread.is_alive()
    assert view._ACTIVE_SCANS is borrowed


@pytest.mark.parametrize("stage", ["before", "after"])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_cleanup_failure_still_drains_other_workers_and_restores_state(stage, error):
    view = _stress_view()
    borrowed, original_threading = view._ACTIVE_SCANS, view.threading
    patch = pytest.MonkeyPatch()
    pools = []
    heartbeat = None
    try:
        with pytest.raises(error, match="shutdown interrupted"):
            with isolated_stress_workers(view, patch):
                for _ in range(2):
                    pool = view.concurrent.futures.ThreadPoolExecutor(max_workers=1)
                    pools.append(pool)
                    assert pool.submit(lambda: "owned").result(timeout=5) == "owned"
                shutdown = pools[0].shutdown

                def failed_shutdown(*args, **kwargs):
                    if stage == "after":
                        shutdown(*args, **kwargs)
                    raise error("shutdown interrupted")

                pools[0].shutdown = failed_shutdown
                stopped = view.threading.Event()
                heartbeat = view.threading.Thread(target=stopped.wait, daemon=True)
                heartbeat.start()
        assert not heartbeat.is_alive()
        assert all(not thread.is_alive() for pool in pools for thread in pool._threads)
        assert view._ACTIVE_SCANS is borrowed
        assert view.threading is original_threading
    finally:
        # Independent cleanup also makes the unfixed-helper counterexample safe.
        for pool in pools:
            concurrent.futures.ThreadPoolExecutor.shutdown(pool, wait=True, cancel_futures=True)
        if heartbeat is not None:
            stopped.set()
            heartbeat.join(timeout=5)
        patch.undo()

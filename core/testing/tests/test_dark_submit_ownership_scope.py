"""The actual submit fixture retires workers while their callback mocks remain live."""

from contextlib import contextmanager
import builtins
import concurrent.futures
import threading
from types import CodeType, ModuleType
import pytest
import core.audit.tests.test_dark_concurrent as native
import core.audit.orchestrator as orch
from core.testing.module_views import module_function_view
from core.testing.state_isolation import pin_user_state_dirs

DEPENDENCIES = ('build_witness_prompt', 'parse_witness_response', 'language_for_file')

@contextmanager
def exercise(tmp_path, phase):
    real = concurrent.futures.ThreadPoolExecutor
    pools, transferred = [], []
    release = threading.Event()
    error = KeyboardInterrupt if 'interrupt' in phase else RuntimeError
    original_submit = native._submit_dark_probes_early
    importer = builtins.__import__
    class Pool(real):
        def __init__(self, *args, **kwargs):
            assert kwargs == {'max_workers': 2}
            super().__init__(*args, **kwargs)
            self.waits, self.futures, self.observed, self.started, self.targets = [], [], [], [], []
            pools.append(self)
        def submit(self, target, *args, **kwargs):
            self.targets.append(target)
            dependencies = tuple(getattr(orch, name) for name in DEPENDENCIES)
            started = threading.Event()
            self.started.append(started)
            def running():
                started.set()
                assert release.wait(5), 'owned callback gate not released'
                live = all(getattr(orch, name, None) is expected for name, expected in zip(DEPENDENCIES, dependencies))
                self.observed.append(live)
                assert live, 'owned callback dependency lifetime expired'
                return target(*args, **kwargs)
            future = super().submit(running)
            self.futures.append(future)
            result = future.result
            def collect(*args, **kwargs):
                release.set()
                value = result(*args, **kwargs)
                if phase.startswith('result-'):
                    raise error('owned result collection failure')
                return value
            owner.setitem(vars(future), 'result', collect)
            assert started.wait(5)
            return future
        def shutdown(self, wait=True, *, cancel_futures=False):
            self.waits.append((wait, cancel_futures))
            if wait:
                release.set()
            return super().shutdown(wait=wait, cancel_futures=cancel_futures)
    futures = ModuleType('concurrent.futures')
    vars(futures).update(vars(concurrent.futures))
    futures.ThreadPoolExecutor = Pool
    root = ModuleType('concurrent')
    vars(root).update(vars(concurrent))
    root.futures = futures
    def local(name, globals=None, locals=None, fromlist=(), level=0):
        if name == 'concurrent.futures' and level == 0:
            return futures if fromlist else root
        return importer(name, globals, locals, fromlist, level)
    def submit(*args, **kwargs):
        view = module_function_view(orch, bindings={'_owned_submit': original_submit}, import_hook=local)
        assert view._owned_submit.__code__ is original_submit.__code__
        output = view._owned_submit(*args, **kwargs)
        transferred.append(output)
        return output
    def length(value):
        if transferred and value is transferred[0][0] and phase.startswith('assert-'):
            raise error('owned assertion failure')
        return len(value)
    function = native.TestSubmitDarkProbes.test_dark_outcomes_submitted
    view = module_function_view(native, bindings={'_owned_case': function, '_submit_dark_probes_early': submit, 'len': length})
    assert view._owned_case.__code__ is function.__code__
    with pytest.MonkeyPatch.context() as owner:
        pin_user_state_dirs(owner, tmp_path / 'state')
        try:
            yield lambda: view._owned_case(native.TestSubmitDarkProbes(), tmp_path), pools, transferred
        finally:
            release.set()
            for pool in pools:
                real.shutdown(pool, wait=True)
                assert all(not worker.is_alive() for worker in pool._threads)


@pytest.mark.parametrize('phase', ['normal', 'assert-error', 'assert-interrupt', 'result-error', 'result-interrupt'])
def test_actual_submit_caller_owns_workers_and_callback_dependencies(tmp_path, phase):
    real = concurrent.futures.ThreadPoolExecutor
    original_submit = native._submit_dark_probes_early
    absent = object()
    original_bindings = {name: vars(orch).get(name, absent) for name in DEPENDENCIES}
    probe_code = next(code for code in original_submit.__code__.co_consts
                      if isinstance(code, CodeType) and code.co_name == '_probe')
    error = KeyboardInterrupt if 'interrupt' in phase else RuntimeError
    with exercise(tmp_path, phase) as (invoke, pools, transferred):
        if phase == 'normal':
            invoke()
        else:
            with pytest.raises(error, match='owned .* failure'):
                invoke()
        assert len(pools) == len(transferred) == 1
        pool = pools[0]
        assert pool.waits == [(True, False)]
        assert len(pool.futures) == len(pool._threads) == 2
        assert all(not worker.is_alive() for worker in pool._threads)
        assert pool.observed == [True, True]
        assert all(target.__code__ is probe_code for target in pool.targets)
        assert all(future.done() for future in pool.futures)
        assert all(concurrent.futures.Future.result(future, timeout=5) is None
                   for future in pool.futures)
        assert concurrent.futures.ThreadPoolExecutor is real
        assert native._submit_dark_probes_early is original_submit
    assert all('result' not in vars(future) for future in pool.futures)
    for name, original in original_bindings.items():
        assert vars(orch).get(name, absent) is original

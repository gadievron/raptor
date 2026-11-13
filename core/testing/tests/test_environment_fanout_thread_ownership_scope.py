"""Actual fan-out guard fixtures retire every registered worker before patch undo."""
from contextlib import contextmanager, nullcontext
import threading
from types import ModuleType
import pytest
import core.audit.tests.test_environment_guard as native
import core.audit.environment as environment
from core.testing.module_views import module_function_view

CASES = ['test_sibling_gates_during_pause_and_releases_on_recovery', 'test_conclusion_releases_paused_worker_promptly', 'test_conclusion_releases_probing_worker_promptly', 'test_sigterm_abort_releases_paused_tick_promptly', 'test_staggered_pausers_release_at_first_conclusion']
HELPER_CASES = (CASES[0], CASES[4])
TUNING = ('WATCHDOG_MAX_PAUSE_S', 'WATCHDOG_POLL_S', 'WATCHDOG_CHECK_INTERVAL_S', 'BREAKER_MAX_PROBE_WAIT_S', 'BREAKER_PROBE_BACKOFF_INITIAL_S', 'BREAKER_PROBE_BACKOFF_MAX_S')

@contextmanager
def exercise(case, phase, fault_index, tmp_path):
    real = threading.Thread
    threads = []
    error = KeyboardInterrupt if 'interrupt' in phase else RuntimeError
    with pytest.MonkeyPatch.context() as patch:
        class Thread(real):
            def __init__(self, *args, **kwargs):
                target = kwargs['target']
                self.native_target = target
                cells = dict(zip(target.__code__.co_freevars, (c.cell_contents for c in target.__closure__)))
                self.guard = cells['g']
                assert type(self.guard) is native.EnvironmentGuard
                self.done = cells.get('done', cells.get('released'))
                self.fs = self.guard._statvfs
                assert type(self.fs) is native._BarrierFs
                self.index, self.joins = len(threads), []
                super().__init__(*args, **kwargs)
                threads.append(self)
            def start(self):
                if self.index == fault_index and phase.startswith('before-'):
                    raise error('owned start failure')
                super().start()
                if self.index == fault_index and phase.startswith('after-'):
                    if self.index:
                        assert self.fs.wait_for_thread(self), 'actual sibling did not measure'
                    elif case == CASES[2]:
                        assert self.fs.first_measure.wait(10), 'actual probe did not measure'
                    else:
                        assert self.fs.paused_measure.wait(10), 'actual watchdog did not pause'
                    raise error('owned start failure')
            def join(self, *args, **kwargs):
                self.joins.append((args, kwargs, tuple(getattr(environment, name) for name in TUNING)))
                return super().join(*args, **kwargs)
        namespace = ModuleType('threading')
        vars(namespace).update(vars(threading))
        namespace.Thread = Thread
        cls = native.TestFanOutPauseParity
        function = getattr(cls, case)
        view = module_function_view(native, bindings={'_owned_case': function, '_owned_tick': cls._tick_in_thread, '_threading': namespace})
        assert view._owned_case.__code__ is function.__code__
        owner = cls()
        owner._tick_in_thread = view._owned_tick.__get__(owner, cls)
        def invoke():
            fixture = getattr(cls, '_retire_tick_workers', None)
            scope = contextmanager(fixture.__wrapped__)(owner, patch) if fixture is not None else nullcontext()
            with scope:
                return view._owned_case(owner, tmp_path, patch)
        try:
            yield invoke, threads, owner
        finally:
            for thread in threads:
                if thread.is_alive():
                    thread.guard._conclude('independent proof retirement')
            for thread in threads:
                if thread.ident is not None:
                    real.join(thread, timeout=10)
                    assert not thread.is_alive()

SCENARIOS = [(case, 'normal', 0) for case in CASES]
SCENARIOS += [(case, phase, 0) for case in CASES for phase in ('before-error', 'after-error', 'before-interrupt', 'after-interrupt')]
SCENARIOS += [(case, phase, 1) for case in HELPER_CASES for phase in ('before-error', 'after-error', 'before-interrupt', 'after-interrupt')]

@pytest.mark.parametrize('case,phase,fault_index', SCENARIOS)
def test_actual_fanout_fixture_retires_workers(case, phase, fault_index, tmp_path):
    real = threading.Thread
    borrowed = {name: getattr(environment, name) for name in TUNING}
    with exercise(case, phase, fault_index, tmp_path) as (invoke, threads, owner):
        if phase == 'normal':
            invoke()
        else:
            error = KeyboardInterrupt if 'interrupt' in phase else RuntimeError
            with pytest.raises(error, match='owned start failure'):
                invoke()
        expected = (2 if case in HELPER_CASES else 1) if phase == 'normal' else fault_index + 1
        assert len(threads) == expected
        started = [thread for thread in threads if thread.ident is not None]
        expected_started = expected if phase == 'normal' else fault_index + int(phase.startswith('after-'))
        assert len(started) == expected_started
        assert all(not thread.is_alive() for thread in threads)
        assert all(thread.done.is_set() == (thread.ident is not None) for thread in threads)
        assert all(bool(thread.joins) == (thread.ident is not None) for thread in threads)
        tuning = tuple(getattr(environment, name) for name in TUNING)
        assert all(thread.joins[-1][2] == tuning for thread in started)
        guard = threads[0].guard
        expected_concluded = case in (CASES[1], CASES[2], CASES[4]) if phase == 'normal' else bool(started)
        assert guard.concluded == expected_concluded
        if phase != 'normal':
            assert vars(threads[0].fs.stat) == vars(native._stat(1 * 1024 * 1024))
        parent = native.TestFanOutPauseParity._tick_in_thread if case in HELPER_CASES else getattr(native.TestFanOutPauseParity, case)
        code = next(c for c in parent.__code__.co_consts if isinstance(c, type(parent.__code__)) and c.co_name == '_run')
        assert all(thread.native_target.__code__ is code for thread in threads)
        assert threading.Thread is real
        assert native._threading is threading
    for name, value in borrowed.items():
        assert getattr(environment, name) is value
    assert '_tick_workers' not in vars(owner)
    assert '_tick_guards' not in vars(owner)

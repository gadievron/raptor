"""Actual serialization callers retire workers before memo/CLI/analyze scopes close."""
from contextlib import ExitStack, contextmanager
from pathlib import Path
import threading
from types import ModuleType
import pytest
import core.audit.tests.test_codeql_sweep_memo as native
import core.audit.codeql_dbs as databases
import core.dataflow.codeql_augmented_run as analyze_module
from core.testing.module_views import module_function_view
from core.testing.module_state import isolated_module_state

CASES = {'prefill': 'test_sweep_waits_for_the_db_lock_then_serves_the_prefill', 'warm': 'test_warmup_and_sweep_never_overlap_an_analyze'}
FLAGS = ('_codeql_channel_warned', '_codeql_warmup_warned', '_codeql_error_streak')

@contextmanager
def exercise(case, phase, tmp_path):
    real = threading.Thread
    release, entered_lock = threading.Event(), threading.Event()
    threads = []
    error = KeyboardInterrupt if 'interrupt' in phase else RuntimeError
    sweep = native.sweep_mod
    with ExitStack() as state:
        state.enter_context(isolated_module_state(sweep, {'_codeql_db_locks': {}}, lock=sweep._codeql_db_locks_guard))
        state.enter_context(isolated_module_state(databases, {'_SRC_INDEX_CACHE': type(databases._SRC_INDEX_CACHE)()}, lock=databases._SRC_INDEX_LOCK))
        with sweep._codeql_channel_guard:
            flags = {name: getattr(sweep, name) for name in FLAGS}
        state.enter_context(isolated_module_state(sweep, flags, lock=sweep._codeql_channel_guard))
        with pytest.MonkeyPatch.context() as patch:
            native._fresh_memo.__wrapped__(patch)
            with contextmanager(native._hermetic_codeql_cli.__wrapped__)(patch):
                original_lock_for = sweep._codeql_db_lock_for
                def lock_for(db_path):
                    lock = original_lock_for(db_path)
                    if case == 'prefill' and phase == 'normal' and threading.current_thread() in threads:
                        assert lock is threads[0].db_lock and lock.locked()
                        entered_lock.set()
                    return lock
                patch.setattr(sweep, '_codeql_db_lock_for', lock_for)
                class Thread(real):
                    def __init__(self, *args, **kwargs):
                        target = kwargs['target']
                        self.native_target = target
                        cells = dict(zip(target.__code__.co_freevars, (c.cell_contents for c in target.__closure__)))
                        self.db = cells['db']
                        self.results = cells.get('results')
                        self.analyze = analyze_module.analyze
                        cells = dict(zip(self.analyze.__code__.co_freevars, (c.cell_contents for c in (self.analyze.__closure__ or ()))))
                        self.active, self.calls = cells.get('active'), cells.get('calls')
                        self.alias, self.warm = native.run_codeql_sweep, sweep.warm_codeql_memo
                        self.memo = sweep._codeql_memo
                        assert type(self.memo) is native.BoundedMemo
                        with sweep._codeql_db_locks_guard:
                            self.db_lock = sweep._codeql_db_locks.get(str(Path(self.db).resolve()))
                        def running(*args, **kwargs):
                            assert release.wait(10), 'owned worker gate not released'
                            return target(*args, **kwargs)
                        kwargs['target'] = running
                        self.joins = []
                        super().__init__(*args, **kwargs)
                        threads.append(self)
                    def start(self):
                        if phase.startswith('before-'):
                            raise error('owned start failure')
                        if phase == 'normal':
                            release.set()
                        super().start()
                        if case == 'prefill' and phase == 'normal':
                            assert entered_lock.wait(10), 'actual sweep did not reach held DB mutex'
                        if phase.startswith('after-'):
                            raise error('owned start failure')
                    def join(self, *args, **kwargs):
                        self.joins.append((args, kwargs))
                        assert analyze_module.analyze is self.analyze
                        assert native.run_codeql_sweep is self.alias
                        assert sweep.warm_codeql_memo is self.warm
                        release.set()
                        return super().join(*args, **kwargs)
                thread_namespace = ModuleType('threading')
                vars(thread_namespace).update(vars(threading))
                thread_namespace.Thread = Thread
                function = getattr(native.TestPerDbAnalyzeSerialization, CASES[case])
                view = module_function_view(native, bindings={'_owned_case': function, 'threading': thread_namespace})
                assert view._owned_case.__code__ is function.__code__
                try:
                    yield lambda: view._owned_case(native.TestPerDbAnalyzeSerialization(), tmp_path, patch), threads, entered_lock
                finally:
                    release.set()
                    for thread in threads:
                        if thread.ident is not None:
                            real.join(thread, timeout=30)
                            assert not thread.is_alive()

@pytest.mark.parametrize('case', ['prefill', 'warm'])
@pytest.mark.parametrize('phase', ['normal', 'before-error', 'after-error', 'before-interrupt', 'after-interrupt'])
def test_actual_serialization_caller_retires_before_fixture_undo(case, phase, tmp_path):
    real = threading.Thread
    sweep = native.sweep_mod
    names = ('_codeql_db_locks', '_codeql_db_lock_for', '_codeql_memo', *FLAGS, 'run_codeql_sweep', 'warm_codeql_memo')
    borrowed = {name: getattr(sweep, name) for name in names}
    old_locks = dict(sweep._codeql_db_locks)
    old_index, old_items = databases._SRC_INDEX_CACHE, tuple(databases._SRC_INDEX_CACHE.items())
    old_alias, old_analyze = native.run_codeql_sweep, analyze_module.analyze
    with exercise(case, phase, tmp_path) as (invoke, threads, entered):
        if phase == 'normal':
            invoke()
        else:
            error = KeyboardInterrupt if 'interrupt' in phase else RuntimeError
            with pytest.raises(error, match='owned start failure'):
                invoke()
        assert len(threads) == 1
        thread = threads[0]
        started = thread.ident is not None
        assert started == (not phase.startswith('before-'))
        assert not thread.is_alive()
        assert bool(thread.joins) == started
        with sweep._codeql_db_locks_guard:
            lock = sweep._codeql_db_locks.get(str(Path(thread.db).resolve()))
        assert lock is None or not lock.locked()
        if case == 'prefill':
            assert len(thread.results) == int(started)
            if started:
                assert type(thread.results[0]) is sweep.SweepResult
                assert thread.results[0].outcome == ('confirmed' if phase == 'normal' else 'error')
            if phase == 'normal':
                assert entered.is_set()
        else:
            assert thread.active['n'] == 0
            assert thread.active['max'] == int(started)
            assert bool(thread.calls) == started
            with thread.memo._lock:
                assert len(thread.memo._values) == (2 if started else 0)
        function = getattr(native.TestPerDbAnalyzeSerialization, CASES[case])
        symbol = '_sweep' if case == 'prefill' else 'warm_codeql_memo'
        code = next(c for c in function.__code__.co_consts if isinstance(c, type(function.__code__)) and symbol in c.co_names)
        assert thread.native_target.__code__ is code
        assert threading.Thread is real
        assert native.threading is threading
    for name, value in borrowed.items():
        assert getattr(sweep, name) is value
    assert sweep._codeql_db_locks == old_locks
    assert databases._SRC_INDEX_CACHE is old_index
    assert tuple(old_index.items()) == old_items
    assert native.run_codeql_sweep is old_alias
    assert analyze_module.analyze is old_analyze

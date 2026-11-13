"""The actual phase-ledger fixture stops and joins its real recorder threads on faults."""

from contextlib import contextmanager
import builtins
import threading
from types import CodeType, ModuleType
import pytest
import core.audit.tests.test_cost_tracker as native
from core.testing.module_views import module_function_view

@contextmanager
def exercise(phase):
    real = threading.Thread
    threads = []
    booked = threading.Event()
    error = KeyboardInterrupt if 'interrupt' in phase else RuntimeError
    with pytest.MonkeyPatch.context() as owner:
        class Thread(real):
            def __init__(self, *args, **kwargs):
                target = kwargs['target']
                self.native_target = target
                closure = dict(zip(target.__code__.co_freevars, (cell.cell_contents for cell in target.__closure__)))
                self.ledger, self.stop = closure['ct'], closure['stop']
                assert type(self.ledger) is native.PhaseCostLedger
                if not threads:
                    record = self.ledger.record_call
                    def record_call(*args, **kwargs):
                        result = record(*args, **kwargs)
                        booked.set()
                        return result
                    marker = self.ledger.start_phase
                    def start_phase(*args, **kwargs):
                        result = marker(*args, **kwargs)
                        if phase.startswith('phase-'):
                            raise error('owned phase marker failure')
                        return result
                    owner.setitem(vars(self.ledger), 'record_call', record_call)
                    owner.setitem(vars(self.ledger), 'start_phase', start_phase)
                self.index, self.joins = len(threads), []
                super().__init__(*args, **kwargs)
                threads.append(self)
            def start(self):
                if self.index == 1 and phase.startswith('before-'):
                    raise error('owned start failure')
                super().start()
                assert booked.wait(5), 'actual ledger did not book a call'
                if self.index == 1 and phase.startswith('after-'):
                    raise error('owned start failure')
            def join(self, *args, **kwargs):
                self.joins.append((args, kwargs))
                return super().join(*args, **kwargs)
        private = ModuleType('threading')
        vars(private).update(vars(threading))
        private.Thread = Thread
        importer = builtins.__import__
        def local(name, globals=None, locals=None, fromlist=(), level=0):
            if name == 'threading' and level == 0:
                return private
            return importer(name, globals, locals, fromlist, level)
        function = native.TestPhaseWallClock.test_markers_tolerate_concurrent_record_call
        view = module_function_view(native, bindings={'_owned_case': function}, import_hook=local)
        assert view._owned_case.__code__ is function.__code__
        try:
            yield lambda: view._owned_case(native.TestPhaseWallClock()), threads
        finally:
            for thread in threads:
                thread.stop.set()
            for thread in threads:
                if thread.ident is not None:
                    real.join(thread, timeout=10)
                    assert not thread.is_alive()


@pytest.mark.parametrize('phase', ['normal', 'before-error', 'before-interrupt', 'after-error', 'after-interrupt', 'phase-error', 'phase-interrupt'])
def test_actual_ledger_caller_stops_and_retires_recorders(phase):
    real = threading.Thread
    record_method = native.PhaseCostLedger.record_call
    marker_method = native.PhaseCostLedger.start_phase
    function = native.TestPhaseWallClock.test_markers_tolerate_concurrent_record_call
    worker_code = next(code for code in function.__code__.co_consts
                       if isinstance(code, CodeType) and code.co_name == 'worker')
    error = KeyboardInterrupt if 'interrupt' in phase else RuntimeError
    with exercise(phase) as (invoke, threads):
        if phase == 'normal':
            invoke()
        else:
            with pytest.raises(error, match='owned .* failure'):
                invoke()
        assert len(threads) == 4
        started = [thread for thread in threads if thread.ident is not None]
        expected = 1 if phase.startswith('before-') else 2 if phase.startswith('after-') else 4
        assert len(started) == expected
        assert all(not thread.is_alive() and thread.stop.is_set() for thread in threads)
        assert all(thread.joins for thread in started)
        assert all(not thread.joins for thread in threads if thread.ident is None)
        assert all(thread.native_target.__code__ is worker_code for thread in threads)
        ledger = threads[0].ledger
        assert ledger.phases['review'].calls > 0
        assert native.PhaseCostLedger.record_call is record_method
        assert native.PhaseCostLedger.start_phase is marker_method
        assert threading.Thread is real
    assert 'record_call' not in vars(ledger)
    assert 'start_phase' not in vars(ledger)

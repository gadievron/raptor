"""Actual warning-reservation caller releases and retires its owned worker."""
from contextlib import ExitStack, contextmanager
import builtins
import threading
from types import ModuleType
import pytest
import core.audit.tests.test_prefilter as native
from core.testing.module_views import module_function_view

@contextmanager
def exercise(phase):
    real = threading.Thread
    threads = []
    error = KeyboardInterrupt if 'interrupt' in phase else RuntimeError
    producer = native._prefilter
    with ExitStack() as ownership, pytest.MonkeyPatch.context() as patch:
        # pytest setattr restores bound logger methods as instance entries.
        # Own the exact borrowed entries outside that patch lifetime.
        for key in ('warning', 'debug'):
            if key in vars(producer.logger):
                ownership.callback(setattr, producer.logger, key, vars(producer.logger)[key])
            else:
                ownership.callback(vars(producer.logger).pop, key, None)
        patch.setattr(producer, '_php_sql_additions_warned', False)
        patch.setattr(producer, '_php_sql_additions_failures', producer._php_sql_additions_failures)
        class Thread(real):
            def __init__(self, *args, **kwargs):
                target = kwargs['target']
                self.native_target = target
                cells = dict(zip(target.__code__.co_freevars, (c.cell_contents for c in target.__closure__)))
                self.results = cells['results']
                warning = producer.logger.warning
                cells = dict(zip(warning.__code__.co_freevars, (c.cell_contents for c in warning.__closure__)))
                self.go, self.started, self.warned_by = cells['go'], cells['started'], cells['warned_by']
                self.warning, self.additions = warning, producer._php_sql_additions
                self.joins = []
                super().__init__(*args, **kwargs)
                threads.append(self)
            def start(self):
                if phase.startswith('before-'):
                    raise error('owned start failure')
                super().start()
                assert self.started.wait(5)
                if phase.startswith('after-'):
                    raise error('owned start failure')
            def join(self, *args, **kwargs):
                self.joins.append((args, kwargs))
                assert producer.logger.warning is self.warning
                assert producer._php_sql_additions is self.additions
                return super().join(*args, **kwargs)
        namespace = ModuleType('threading')
        vars(namespace).update(vars(threading))
        namespace.Thread = Thread
        real_import = builtins.__import__
        def importer(name, globals=None, locals=None, fromlist=(), level=0):
            if name == 'threading' and level == 0:
                return namespace
            return real_import(name, globals, locals, fromlist, level)
        function = native.TestPhpSqlInjectionFailSafe.test_concurrent_failure_skips_a_pending_warning
        view = module_function_view(native, bindings={'_owned_case': function}, import_hook=importer)
        assert view._owned_case.__code__ is function.__code__
        try:
            yield lambda: view._owned_case(native.TestPhpSqlInjectionFailSafe(), patch), threads
        finally:
            for thread in threads:
                thread.go.set()
            for thread in threads:
                if thread.ident is not None:
                    real.join(thread, timeout=5)
                    assert not thread.is_alive()

@pytest.mark.parametrize('phase', ['normal', 'before-error', 'after-error', 'before-interrupt', 'after-interrupt'])
def test_actual_warning_caller_retires_before_patch_undo(phase):
    real = threading.Thread
    producer = native._prefilter
    before = (producer._php_sql_additions_warned, producer._php_sql_additions_failures, producer._php_sql_additions)
    logger_before = {key: (key in vars(producer.logger), vars(producer.logger).get(key)) for key in ('warning', 'debug')}
    with exercise(phase) as (invoke, threads):
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
        assert thread.go.is_set()
        expected = {'first': {3}, 'second': {3}} if phase == 'normal' else {'first': {3}} if started else {}
        assert thread.results == expected
        assert thread.warned_by == (['reserving'] if started else [])
        assert producer._php_sql_additions_failures == before[1] + len(expected)
        assert producer._php_sql_additions_warned is False
        function = native.TestPhpSqlInjectionFailSafe.test_concurrent_failure_skips_a_pending_warning
        code = next(c for c in function.__code__.co_consts if isinstance(c, type(function.__code__)) and c.co_name == 'first')
        assert thread.native_target.__code__ is code
        assert threading.Thread is real
    assert (producer._php_sql_additions_warned, producer._php_sql_additions_failures, producer._php_sql_additions) == before
    for key, (present, value) in logger_before.items():
        assert (key in vars(producer.logger)) == present
        assert vars(producer.logger).get(key) is value

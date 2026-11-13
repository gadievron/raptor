"""Real scanner join futures retire their sole owned worker on every exit."""
from contextlib import contextmanager
import builtins
import concurrent.futures
import importlib
from pathlib import Path
import sys
import threading
from types import ModuleType
from unittest.mock import patch

import pytest

from core.testing.logging_state import isolated_cli_logging
from core.testing.module_registry import fresh_module_tree
from core.testing.module_views import module_function_view
from core.testing.state_isolation import pin_user_state_dirs

METHODS = ['test_keyboard_interrupt_runs_abort_and_reraises',
           'test_stage_exception_demoted_no_abort', 'test_success_passes_sarifs_through']

@contextmanager
def probe(tmp_path, method, submit_error=None):
    real = concurrent.futures.ThreadPoolExecutor
    pools = []
    class Queue:
        def __init__(self, queue, pool):
            self.queue, self.pool = queue, pool
        def check(self, value):
            if value is None:
                self.pool.retiring.set()
                assert self.pool.release.wait(5), 'owned retirement gate not released'
            return value
        def get_nowait(self):
            return self.check(self.queue.get_nowait())
        def get(self, *args, **kwargs):
            return self.check(self.queue.get(*args, **kwargs))
        def put(self, value):
            return self.queue.put(value)
    class Pool(real):
        def __init__(self, *args, **kwargs):
            assert kwargs == {'max_workers': 1}
            super().__init__(*args, **kwargs)
            self.release, self.retiring = threading.Event(), threading.Event()
            self.waits = []
            self._work_queue = Queue(self._work_queue, self)
            pools.append(self)
        def submit(self, *args, **kwargs):
            future = super().submit(*args, **kwargs)
            self.future = future
            if submit_error:
                raise submit_error('owned submit failure')
            return future
        def shutdown(self, wait=True, *, cancel_futures=False):
            self.waits.append(wait)
            if wait:
                self.release.set()
            return super().shutdown(wait=wait, cancel_futures=cancel_futures)
    name = 'packages.static-analysis.tests.test_scanner'
    with (pytest.MonkeyPatch.context() as owner, isolated_cli_logging(),
          fresh_module_tree(name), patch.object(sys, 'path', sys.path.copy())):
        root = Path(__file__).resolve().parents[3]
        pin_user_state_dirs(owner, tmp_path / 'state')
        owner.setenv('RAPTOR_DIR', str(root))
        native = importlib.import_module(name)
        case = native.TestJoinCodeQLStage()
        original = case._future
        function = getattr(original, '__wrapped__', original)
        namespace = ModuleType('concurrent.futures')
        vars(namespace).update(vars(concurrent.futures))
        namespace.ThreadPoolExecutor = Pool
        importer = builtins.__import__
        def local(name, globals=None, locals=None, fromlist=(), level=0):
            if name == 'concurrent.futures' and level == 0:
                return namespace
            return importer(name, globals, locals, fromlist, level)
        view = module_function_view(native, bindings={'_owned_future': function}, import_hook=local)
        assert view._owned_future.__code__ is function.__code__
        invoke = contextmanager(view._owned_future) if hasattr(original, '__wrapped__') else view._owned_future
        owner.setitem(vars(case), '_future', invoke)
        try:
            yield native, case, pools
        finally:
            for pool in pools:
                pool.release.set()
                real.shutdown(pool, wait=True)
                assert all(not worker.is_alive() for worker in pool._threads)

def invoke(case, method, capsys):
    if method == 'test_stage_exception_demoted_no_abort':
        getattr(case, method)(capsys)
    else:
        getattr(case, method)()


@pytest.mark.parametrize('method', METHODS)
@pytest.mark.parametrize('phase', ['normal', 'body-error', 'body-interrupt',
                                  'submit-error', 'submit-interrupt'])
def test_actual_join_fixture_retires_worker(tmp_path, capsys, method, phase):
    from contextlib import nullcontext

    error = KeyboardInterrupt if 'interrupt' in phase else RuntimeError
    submit_error = error if phase.startswith('submit-') else None
    real = concurrent.futures.ThreadPoolExecutor
    with probe(tmp_path, method, submit_error=submit_error) as (native, case, pools):
        original = case._future

        @contextmanager
        def fail_after_body(target):
            with original(target) as future:
                yield future
                raise error('owned body failure')

        with pytest.MonkeyPatch.context() as owner:
            if phase.startswith('body-'):
                owner.setitem(vars(case), '_future', fail_after_body)
            message = 'owned submit failure' if submit_error else 'owned body failure'
            expected = (pytest.raises(error, match=message)
                        if phase != 'normal' else nullcontext())
            with expected:
                invoke(case, method, capsys)
            assert len(pools) == 1
            pool = pools[0]
            assert pool.waits == [True]
            assert pool.future.done()
            assert pool.retiring.is_set() and pool.release.is_set()
            assert len(pool._threads) == 1
            assert all(not worker.is_alive() for worker in pool._threads)
            assert concurrent.futures.ThreadPoolExecutor is real
        assert case._future is original

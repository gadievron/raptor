"""Native parser fixture workers complete before cache bindings are restored."""

import threading

import pytest

from core.inventory.tests import test_ts_cache as native
from core.testing.module_bindings import patch_module_attribute

pytest_plugins = ["core.inventory.tests.test_ts_cache"]


@pytest.mark.parametrize("operation,after,error", [
    (operation, after, error)
    for operation in ("start", "join") for after in (False, True)
    for error in (OSError, KeyboardInterrupt, SystemExit)
] + [(None, False, None)])
def test_real_parser_worker_retires_on_boundary_errors(
    fresh_caches, monkeypatch, operation, after, error,
):
    workers, parsers = [], []
    entered, release = threading.Event(), threading.Event()
    failure = error("owned parser boundary failure") if error else None
    fired = False
    real_parser = native.extractors._ts_parser_for
    borrowed_threading, borrowed_extractors = native.threading, native.extractors

    def parse(*a, **k):
        parser = real_parser(*a, **k)
        parsers.append((threading.current_thread(), parser))
        return parser

    class Worker(threading.Thread):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            workers.append(self)

        def run(self):
            entered.set()
            assert release.wait(10), "owned parser safety release timed out"
            super().run()

        def boundary(self, name, action):
            nonlocal fired
            selected = operation == name and not fired
            if selected:
                fired = True
                if not after:
                    raise failure
            value = action()
            if selected:
                raise failure
            return value

        def start(self):
            def starting():
                threading.Thread.start(self)
                assert entered.wait(10)
            self.boundary("start", starting)

        def join(self, timeout=None):
            def joining():
                release.set()
                threading.Thread.join(self, timeout)
            self.boundary("join", joining)

    with monkeypatch.context() as patch:
        patch_module_attribute(patch, native, "threading", "Thread", Worker)
        patch_module_attribute(patch, native, "extractors", "_ts_parser_for", parse)
        try:
            if error:
                with pytest.raises(error) as caught:
                    native.test_parser_cache_is_per_thread(fresh_caches)
                assert caught.value is failure
                assert fired
            else:
                native.test_parser_cache_is_per_thread(fresh_caches)
            assert len(workers) == 1 and not workers[0].is_alive()
            assert parsers[0][0] is threading.current_thread()
            assert parsers[0][1] is not None
            if workers[0].ident is not None:
                assert len(parsers) == 2 and parsers[1][0] is workers[0]
                assert parsers[1][1] is not None
                assert parsers[1][1] is not parsers[0][1]
            else:
                assert len(parsers) == 1
        finally:
            # Observe native retirement above; guard the real cache fixture's
            # lifetime even when an ownership assertion regresses.
            release.set()
            for worker in workers:
                if worker.ident is not None:
                    threading.Thread.join(worker, 10)
                    assert not worker.is_alive()
    assert native.threading is borrowed_threading
    assert native.extractors is borrowed_extractors

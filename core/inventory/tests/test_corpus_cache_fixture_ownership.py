"""Actual corpus fixture workers retire before their cache state is removed."""

import threading

import pytest

from core.inventory.tests import test_corpus_cache_lifecycle as native
from core.testing.module_bindings import patch_module_attribute

private_state = native.private_state
case = native.case


@pytest.mark.parametrize("position,error", [(position, error)
    for position in (0, 1) for error in (OSError, KeyboardInterrupt, SystemExit)]
    + [(None, None)])
def test_native_prepare_workers_retire_across_join_errors(
    case, monkeypatch, position, error,
):
    workers, joined = [], []
    release = threading.Event()
    failure = error("owned error after native join") if error else None
    fired = False

    class Worker(threading.Thread):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            workers.append(self)

        def run(self):
            super().run()
            if self is workers[1]:
                assert release.wait(10), "owned second worker was never released"

        def join(self, *a, **k):
            nonlocal fired
            joined.append(self)
            if self is workers[1]:
                release.set()
            super().join(*a, **k)
            if error and self is workers[position] and not fired:
                fired = True
                raise failure

    with monkeypatch.context() as patch:
        patch_module_attribute(patch, native, "threading", "Thread", Worker)
        try:
            if error:
                with pytest.raises(error) as caught:
                    native.test_concurrent_preparations_build_once(case, patch)
                assert caught.value is failure
                assert fired
            else:
                native.test_concurrent_preparations_build_once(case, patch)
            assert len(workers) == 2
            assert joined == workers
            assert all(not worker.is_alive() for worker in workers)
            # Even an error reported by the first completed join must not
            # prevent the second actual preparation or its retirement.
            assert case[-1]["calls"] == 1
        finally:
            # Native cleanup is observed above. Protect the original fixture
            # lifetime from regressions before its hardened tree removal.
            release.set()
            for worker in workers:
                if worker.ident is not None:
                    threading.Thread.join(worker, 15)
                    assert not worker.is_alive()

from pathlib import Path
from tempfile import TemporaryDirectory
import threading
from types import ModuleType

import pytest
from core.testing.tests._terminal_metadata_workers import load_worker_module

@pytest.mark.parametrize("position,after", [(0, False), (0, True), (1, False), (1, True)])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_partial_start_retires_terminal_writers(position, after, error):
    failure = error("owned terminal writer startup fault")
    waiting = threading.Event()
    roots, workers, barriers, stopped = [], [], [], []

    class Directory:
        def __init__(self):
            self.owned = TemporaryDirectory()

        def __enter__(self):
            root = self.owned.__enter__()
            roots.append(Path(root))
            return root

        def __exit__(self, *args):
            assert all(not worker.is_alive() for worker in workers)
            return self.owned.__exit__(*args)

    class Barrier(threading.Barrier):
        def __init__(self, parties):
            assert parties == 2
            super().__init__(parties)
            barriers.append(self)

        def wait(self, timeout=None):
            waiting.set()
            return super().wait(timeout=timeout)

    class Worker(threading.Thread):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.position = len(workers)
            workers.append(self)

        def run(self):
            try:
                super().run()
            except threading.BrokenBarrierError as exc:
                stopped.append(exc)

        def start(self):
            selected = self.position == position
            if selected and not after:
                if self.position:
                    assert waiting.wait(5)
                raise failure
            super().start()
            if selected:
                assert waiting.wait(5)
                raise failure

    thread_view = ModuleType("threading")
    vars(thread_view).update(vars(threading))
    thread_view.Thread, thread_view.Barrier = Worker, Barrier
    native = load_worker_module(thread_view, Directory)
    case = native.TestUpdateStatusConcurrency("test_racing_terminal_writers_keep_first_verdict")
    try:
        with pytest.raises(error) as caught:
            case.test_racing_terminal_writers_keep_first_verdict()
        assert caught.value is failure
        assert len(roots) == 1 and not roots[0].exists()
        assert len(workers) == 2 and all(not worker.is_alive() for worker in workers)
    finally:
        for barrier in barriers:
            barrier.abort()
        for worker in workers:
            if worker.ident is not None:
                threading.Thread.join(worker, timeout=10)
                assert not worker.is_alive()
    assert not stopped


def test_actual_terminal_writers_preserve_first_verdict():
    native = load_worker_module()
    case = native.TestUpdateStatusConcurrency("test_racing_terminal_writers_keep_first_verdict")
    case.test_racing_terminal_writers_keep_first_verdict()

"""The progress FIFO watchdog owns both unwind and peer retirement."""

import pytest

from ._progress_fifo_ownership import exercise


@pytest.mark.parametrize("phase", ["normal", "before-error", "before-interrupt", "after-error", "after-interrupt"])
def test_progress_fifo_watchdog_retires_on_start_failure(phase, tmp_path):
    error = KeyboardInterrupt if "interrupt" in phase else RuntimeError
    with exercise(phase, tmp_path) as (invoke, workers, done, opening):
        if phase == "normal":
            invoke()
        else:
            with pytest.raises(error, match="owned start failure"):
                invoke()
        assert len(workers) == 1
        worker = workers[0]
        assert not worker.is_alive()
        assert bool(worker.joins) is (worker.ident is not None)
        assert done[0].is_set() is (worker.ident is not None)
        assert opening.is_set() is phase.startswith("after-")

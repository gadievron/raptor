"""The delayed quiescence transition cannot outlive its test owner."""

import pytest

from ._journal_queue_ownership import exercise


@pytest.mark.parametrize("phase", ["normal", "before-error", "before-interrupt", "after-error", "after-interrupt"])
def test_queue_transition_worker_retires_on_start_failure(phase):
    error = KeyboardInterrupt if "interrupt" in phase else RuntimeError
    with exercise(phase) as (invoke, workers):
        if phase == "normal":
            invoke()
        else:
            with pytest.raises(error, match="owned start failure"):
                invoke()
        assert len(workers) == 1
        worker = workers[0]
        assert not worker.is_alive()
        assert bool(worker.joins) is (worker.ident is not None)
        assert worker.queue.drain_state()[2] is phase.startswith("before-")

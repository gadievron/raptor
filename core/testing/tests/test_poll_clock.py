"""Polling fakes stay private to their consumer and unwind on every exit."""

from contextlib import nullcontext
import time
from types import ModuleType

import pytest

from core.testing.poll_clock import install_poll_clock


@pytest.mark.parametrize("error", [None, RuntimeError, KeyboardInterrupt])
def test_poll_clock_advances_only_its_consumer_and_restores_binding(error):
    consumer = ModuleType("owned_poll_consumer")
    consumer.time = time
    inherited = dict(vars(time))
    expected = pytest.raises(error) if error is not None else nullcontext()
    with expected:
        with pytest.MonkeyPatch.context() as scope:
            clock = install_poll_clock(scope, consumer)
            for seconds in (0.125, 0.25, 0.125):
                consumer.time.sleep(seconds)
            assert consumer.time.monotonic() == 0.5
            assert clock.sleeps == [0.125, 0.25, 0.125]
            assert consumer.time.process_time is time.process_time
            assert vars(time) == inherited
            if error is not None:
                raise error("owned polling failure")
    assert consumer.time is time
    assert vars(time) == inherited

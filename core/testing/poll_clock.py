"""Advance incidental polling waits without changing the shared process clock."""

from core.testing.module_bindings import patch_module_attribute


class PollClock:
    """A single waiter's monotonic clock; sleeping advances logical seconds."""

    def __init__(self):
        self.seconds = 0.0
        self.sleeps = []

    def monotonic(self):
        return self.seconds

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.seconds += seconds


def install_poll_clock(monkeypatch, consumer):
    """Own only consumer.time's polling functions until monkeypatch unwinds.

    Use for caller-policy tests whose real retry loop matters but whose timer
    is incidental. Keep real-time deadline tests at the shared implementation.
    This clock is for one polling waiter, not concurrent timer arbitration.
    """
    clock = PollClock()
    patch_module_attribute(monkeypatch, consumer, "time", "monotonic", clock.monotonic)
    patch_module_attribute(monkeypatch, consumer, "time", "sleep", clock.sleep)
    return clock

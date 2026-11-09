"""Owned test alarms that retain a caller's real-time deadline."""

from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
import math
import signal
import time


@dataclass(eq=False)
class _Alarm:
    due: float
    handler: object
    interval: float = 0


class _Alarms:
    def __init__(self, handler, delay, interval, started):
        self.interval = interval
        self.borrowed = _Alarm(started + delay, handler, interval) if delay else None
        self.alarms: list[_Alarm] = [self.borrowed] if self.borrowed else []

    def arm(self):
        delay = (max(1e-6, min(item.due for item in self.alarms) - time.monotonic())
                 if self.alarms else 0)
        signal.setitimer(signal.ITIMER_REAL, delay)

    def discard(self, item):
        if item in self.alarms:
            self.alarms.remove(item)
        self.arm()

    def dispatch(self, signum, frame):
        item = min(self.alarms, key=lambda item: item.due)
        if item.interval:
            elapsed = max(0, time.monotonic() - item.due)
            item.due += (math.floor(elapsed / item.interval) + 1) * item.interval
        else:
            self.alarms.remove(item)
        self.arm()
        if item.handler == signal.SIG_IGN:
            return
        if item.handler == signal.SIG_DFL:
            signal.signal(signal.SIGALRM, signal.SIG_DFL)
            signal.raise_signal(signum)
        else:
            assert callable(item.handler)
            item.handler(signum, frame)

    def restore_timer(self):
        delay = (max(1e-6, self.borrowed.due - time.monotonic())
                 if self.borrowed is not None and self.borrowed in self.alarms else 0)
        signal.setitimer(signal.ITIMER_REAL, delay, self.interval)


@contextmanager
def alarm_after(seconds, handler):
    """Bound a POSIX test without cancelling or delaying a borrowed alarm.

    An earlier borrowed deadline still calls its original handler. Repeating
    timers retain their interval; a handled one-shot is not resurrected.
    Nested owners share the same deadline queue and retire only their entry.
    """
    if seconds <= 0:
        raise ValueError("an alarm needs a positive duration")
    if not callable(handler):
        raise TypeError("an owned alarm needs a callable handler")
    previous_handler = signal.getsignal(signal.SIGALRM)
    owner = getattr(previous_handler, "__self__", None)
    started = time.monotonic()
    item = _Alarm(started + seconds, handler)
    if isinstance(owner, _Alarms):
        with ExitStack() as cleanup:
            cleanup.callback(owner.discard, item)
            owner.alarms.append(item)
            owner.arm()
            yield
        return
    delay, interval = signal.getitimer(signal.ITIMER_REAL)
    owner = _Alarms(previous_handler, delay, interval, started)
    owner.alarms.append(item)
    with ExitStack() as cleanup:
        cleanup.callback(owner.restore_timer)
        cleanup.callback(signal.signal, signal.SIGALRM, previous_handler)
        cleanup.callback(signal.setitimer, signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, owner.dispatch)
        owner.arm()
        yield

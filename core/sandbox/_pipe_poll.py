"""Shared read readiness for sandbox pipes, without FD_SETSIZE limits."""

import math
import select
from collections.abc import Iterable


def readable_fds(fds: Iterable[int], timeout: float | None) -> list[int]:
    """Read readiness without select()'s fixed descriptor-number limit."""
    return ready_fds(fds, (), timeout)[0]


def ready_fds(read_fds: Iterable[int], write_fds: Iterable[int],
              timeout: float | None) -> tuple[list[int], list[int]]:
    """Read/write readiness for owned pipes, including HUP and error wakes."""
    readers, writers = list(read_fds), list(write_fds)
    if not readers and not writers:
        return [], []
    masks = {fd: select.POLLIN for fd in readers}
    for fd in writers:
        masks[fd] = masks.get(fd, 0) | select.POLLOUT
    poller = select.poll()
    for fd, mask in masks.items():
        poller.register(fd, mask)
    # poll's C timeout is a signed int. Long waits can be revisited by
    # their caller's absolute deadline without overflowing that argument.
    milliseconds = -1 if timeout is None else max(0, math.ceil(min(timeout, 2147483.647) * 1000))
    events = dict(poller.poll(milliseconds))
    terminal = select.POLLHUP | select.POLLERR | select.POLLNVAL
    return ([fd for fd in readers if events.get(fd, 0) & (select.POLLIN | terminal)],
            [fd for fd in writers if events.get(fd, 0) & (select.POLLOUT | terminal)])

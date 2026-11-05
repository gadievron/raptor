"""Shared read readiness for sandbox pipes, without FD_SETSIZE limits."""

import math
import select
from collections.abc import Iterable


def readable_fds(fds: Iterable[int], timeout: float | None) -> list[int]:
    """Read readiness without select()'s fixed descriptor-number limit."""
    descriptors = list(fds)
    if not descriptors:
        return []
    poller = select.poll()
    for fd in descriptors:
        poller.register(fd, select.POLLIN)
    milliseconds = -1 if timeout is None else max(0, math.ceil(timeout * 1000))
    # HUP/ERR are readiness too: read() must collect buffered bytes or EOF.
    return [fd for fd, events in poller.poll(milliseconds)]

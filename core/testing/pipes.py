"""Transfer test pipe ownership only after all allocations and fork succeed."""

from contextlib import suppress
import os


def fork_with_pipes(count):
    """Return an owned child PID and pipe pairs, closing pipes on setup failure.

    After a successful fork, the test owns each descriptor in both branches
    and must retain its normal parent/child close and wait protocol.
    """
    pairs = []
    try:
        for _ in range(count):
            pairs.append(os.pipe())
        pid = os.fork()
    except BaseException:
        for pair in reversed(pairs):
            for fd in pair:
                with suppress(OSError):
                    os.close(fd)
        raise
    return pid, pairs

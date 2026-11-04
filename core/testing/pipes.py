"""Guard pipe acquisition until test setup transfers ownership."""

from contextlib import contextmanager, suppress
import os


@contextmanager
def pipes_for_setup(count):
    """Yield pipe pairs; close them only if allocation or guarded setup fails.

    Use this around setup before any descriptor is handed off or closed.
    A normal exit transfers ownership to the test's parent/child protocol.
    """
    pairs = []
    try:
        for _ in range(count):
            pairs.append(os.pipe())
        yield pairs
    except BaseException:
        for pair in reversed(pairs):
            for fd in pair:
                with suppress(OSError):
                    os.close(fd)
        raise


def fork_with_pipes(count):
    """Return an owned child PID and pipe pairs, closing pipes on setup failure.

    After a successful fork, the test owns each descriptor in both branches
    and must retain its normal parent/child close and wait protocol.
    """
    with pipes_for_setup(count) as pairs:
        pid = os.fork()
    return pid, pairs

"""Name a Unix socket without changing its operator-selected directory."""

from contextlib import contextmanager
import os
from pathlib import Path
import sys


@contextmanager
def socket_address(path):
    path = Path(path)
    if len(os.fsencode(path)) <= 100:
        yield str(path)
        return
    if sys.platform != "linux":
        raise ValueError("Unix socket path is too long; select a shorter private runtime base")
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        yield f"/proc/self/fd/{descriptor}/{path.name}"
    finally:
        os.close(descriptor)

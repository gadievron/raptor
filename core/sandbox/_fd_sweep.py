"""Close ambient Linux descriptors without trusting a reduced NOFILE limit.

Resolve libc before fork. The child must not import modules or inspect paths
that its own Landlock policy deliberately hides. Existing descriptors remain
valid above both reduced rlimits and arbitrary numeric sweep ceilings.
"""
from __future__ import annotations

import ctypes
import errno
import os
import platform
import sys

_close_range = None
if sys.platform == 'linux':
    _libc = ctypes.CDLL(None, use_errno=True)
    _close_range = getattr(_libc, 'close_range', None)
    if _close_range is not None:
        _close_range.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_int]
        _close_range.restype = ctypes.c_int
    elif platform.machine() in ('x86_64', 'aarch64'):
        # Same syscall number on the two architectures supported by _spawn;
        # older libc need not export a wrapper for a newer running kernel.
        _syscall = _libc.syscall
        _syscall.argtypes = [ctypes.c_long]
        _syscall.restype = ctypes.c_long

        def _close_range(first, last, flags):
            return _syscall(436, ctypes.c_uint(first), ctypes.c_uint(last),
                            ctypes.c_uint(flags))


def close_fds_except(keep) -> None:
    """Post-fork sweep; retain stdio and *keep*, or refuse to exec.

    close_range covers the entire descriptor table, independently of procfs
    access and rlimits. Enumeration is a safe compatibility fallback when
    the syscall is missing or externally blocked. If neither method works,
    fail closed instead of executing with an incomplete descriptor sweep.
    """
    keep = {fd for fd in keep if fd is not None and fd > 2}
    if _close_range is not None:
        first = 3
        for descriptor in sorted(keep):
            if first < descriptor and _close_range(first, descriptor - 1, 0) != 0:
                break
            first = descriptor + 1
        else:
            if _close_range(first, 0xffffffff, 0) == 0:
                return
    try:
        opened = [int(name) for name in os.listdir('/proc/self/fd')]
    except (OSError, ValueError) as exc:
        raise OSError(errno.EPERM,
                      'cannot close ambient descriptors: close_range and '
                      'procfs enumeration unavailable; refusing exec') from exc
    for descriptor in opened:
        if descriptor > 2 and descriptor not in keep:
            try:
                os.close(descriptor)
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    raise

"""Publish an owned directory without replacing any destination entry."""

import ctypes
import errno
import os
from pathlib import Path
import stat
import sys


def _rename_without_replace(source: bytes, destination: bytes) -> None:
    """Use the host's atomic exclusive-rename operation; never emulate it."""
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        if sys.platform == 'linux':
            operation = libc.renameat2
            operation.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                                  ctypes.c_char_p, ctypes.c_uint]
            arguments = (-100, source, -100, destination, 1)  # AT_FDCWD, RENAME_NOREPLACE
        elif sys.platform == 'darwin':
            operation = libc.renamex_np
            operation.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
            arguments = (source, destination, 4)  # RENAME_EXCL
        else:
            raise AttributeError('no exclusive rename API')
    except AttributeError as exc:
        raise OSError(errno.ENOTSUP, 'exclusive directory publication is unavailable') from exc
    operation.restype = ctypes.c_int
    ctypes.set_errno(0)
    if operation(*arguments) != 0:
        code = ctypes.get_errno() or errno.EIO
        raise OSError(code, os.strerror(code), os.fsdecode(source), None, os.fsdecode(destination))


def publish_new_directory(source: str | Path, destination: str | Path) -> None:
    """Atomically move a real directory to an absent name on the same filesystem.

    Every occupied destination, including an empty directory or dangling link,
    is refused by the rename itself. Callers own source cleanup on failure.
    The directory and its files must already be complete; this provides atomic
    visibility, not fsync durability. Unsupported hosts/filesystems fail without
    falling back to a check-then-rename operation or copying a partial tree.

    Linux: renameat2(RENAME_NOREPLACE), man7.org/linux/man-pages/man2/rename.2.html.
    macOS: renamex_np(RENAME_EXCL), Apple xnu bsd/sys/stdio.h.
    """
    source_path = os.path.abspath(os.fspath(source))
    destination_path = os.path.abspath(os.fspath(destination))
    source_bytes, destination_bytes = os.fsencode(source_path), os.fsencode(destination_path)
    if b'\0' in source_bytes or b'\0' in destination_bytes:
        raise ValueError('embedded null byte')
    if not stat.S_ISDIR(os.lstat(source_path).st_mode):
        raise NotADirectoryError(errno.ENOTDIR, 'publication source must be a real directory', source_path)
    if source_path == destination_path:
        raise FileExistsError(errno.EEXIST, 'publication destination already exists', destination_path)
    _rename_without_replace(source_bytes, destination_bytes)

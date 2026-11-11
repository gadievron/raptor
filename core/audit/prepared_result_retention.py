"""Complete durable result retention; an ACK is provenance, not semantic proof."""
from __future__ import annotations

from dataclasses import asdict
import math
import os
from pathlib import Path
import re
import stat
from uuid import uuid4

from core.json import dumps_canonical
from core.source.streams import owned_fd
from .sweep import SweepResult

RESULT_DIRECTORY = "prepared-smt-results"
MAX_RESULT_BYTES = 10 * 1024 * 1024
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _json_values_only(value: object) -> None:
    """Refuse coercion: the canonical encoder otherwise stringifies objects."""
    if value is None or type(value) in (str, int, bool):
        return
    if isinstance(value, float) and type(value) is float and math.isfinite(value):
        return
    if isinstance(value, list) and type(value) is list:
        for item in value:
            _json_values_only(item)
        return
    if isinstance(value, dict) and type(value) is dict and all(type(key) is str for key in value):
        for item in value.values():
            _json_values_only(item)
        return
    raise ValueError("checker result contains a non-JSON value")


def _result_bytes(result: SweepResult) -> bytes:
    if not isinstance(result, SweepResult):
        raise TypeError("retention requires an existing SweepResult")
    payload = asdict(result)
    _json_values_only(payload)
    encoded = (dumps_canonical(payload) + "\n").encode("utf-8")
    if len(encoded) > MAX_RESULT_BYTES:
        raise ValueError("checker result exceeds retention byte limit")
    return encoded


def _open_output_directory(path: Path) -> int:
    """Anchor every existing output path component without following links."""
    if ".." in path.parts:
        raise ValueError("output directory contains traversal")
    fd = os.open(path.anchor or ".", _DIRECTORY_FLAGS)  # raw-open: O_DIRECTORY|O_NOFOLLOW pins directory handles without reading file bytes.
    try:
        parts = path.parts[1:] if path.anchor else path.parts
        for part in parts:
            previous = fd
            fd = os.open(part, _DIRECTORY_FLAGS, dir_fd=previous)  # raw-open: O_DIRECTORY|O_NOFOLLOW pins directory handles without reading file bytes.
            with owned_fd(previous, close_fd=os.close):
                pass
        return fd
    except BaseException:
        with owned_fd(fd, close_fd=os.close):
            raise


def _read_matches(directory_fd: int, filename: str, encoded: bytes) -> bool:
    fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                 dir_fd=directory_fd)
    with owned_fd(fd, close_fd=os.close):
        current = os.fstat(fd)
        if not stat.S_ISREG(current.st_mode) or current.st_size != len(encoded):
            return False
        retained = bytearray()
        while len(retained) <= len(encoded):
            chunk = os.read(fd, min(65536, len(encoded) + 1 - len(retained)))
            if not chunk:
                break
            retained.extend(chunk)
        if retained != encoded:
            return False
        linked = os.stat(filename, dir_fd=directory_fd, follow_symlinks=False)
        return (linked.st_dev, linked.st_ino) == (current.st_dev, current.st_ino)


def retain_smt_result(out_dir: Path, result: SweepResult) -> str:
    """ACK only after exclusive creation, file/directory fsync and readback.

    Unsupported/oversized payloads and filesystem failures raise. Existing
    artifacts are never replaced. Cleanup failures may leave an unacknowledged
    file, which must never be consumed as an admitted fact.
    """
    encoded = _result_bytes(result)
    root_fd = _open_output_directory(Path(out_dir))
    with owned_fd(root_fd, close_fd=os.close):
        filename = uuid4().hex + ".json"
        try:
            os.mkdir(RESULT_DIRECTORY, mode=0o700, dir_fd=root_fd)
        except FileExistsError:
            pass
        directory_fd = os.open(RESULT_DIRECTORY, _DIRECTORY_FLAGS, dir_fd=root_fd)  # raw-open: O_DIRECTORY|O_NOFOLLOW pins directory handles without reading file bytes.
        with owned_fd(directory_fd, close_fd=os.close):
            created = False
            try:
                os.fsync(root_fd)
                fd = os.open(filename, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=directory_fd)
                created = True
                with owned_fd(fd, close_fd=os.close):
                    remaining = memoryview(encoded)
                    while remaining:
                        written = os.write(fd, remaining)
                        if written <= 0:
                            raise OSError("incomplete checker result write")
                        remaining = remaining[written:]
                    os.fsync(fd)
                os.fsync(directory_fd)
                if not _read_matches(directory_fd, filename, encoded):
                    raise OSError("retained result failed complete readback")
                linked = os.stat(RESULT_DIRECTORY, dir_fd=root_fd, follow_symlinks=False)
                opened = os.fstat(directory_fd)
                if (linked.st_dev, linked.st_ino) != (opened.st_dev, opened.st_ino):
                    raise OSError("retained result directory changed before acknowledgement")
                return f"{RESULT_DIRECTORY}/{filename}"
            except BaseException:
                if created:
                    try:
                        os.unlink(filename, dir_fd=directory_fd)
                    except BaseException:
                        pass  # An active operation error keeps precedence.
                raise


def retained_smt_result_matches(out_dir: Path, reference: str, result: SweepResult) -> bool:
    """Revalidate the complete retained result; missing/changed data is unknown."""
    if not isinstance(reference, str) or re.fullmatch(
            r"prepared-smt-results/[0-9a-f]{32}\.json", reference) is None:
        return False
    try:
        encoded = _result_bytes(result)
        root_fd = _open_output_directory(Path(out_dir))
        with owned_fd(root_fd, close_fd=os.close):
            directory_fd = os.open(RESULT_DIRECTORY, _DIRECTORY_FLAGS, dir_fd=root_fd)  # raw-open: O_DIRECTORY|O_NOFOLLOW pins directory handles without reading file bytes.
            with owned_fd(directory_fd, close_fd=os.close):
                if not _read_matches(directory_fd, reference.split("/")[1], encoded):
                    return False
                linked = os.stat(RESULT_DIRECTORY, dir_fd=root_fd, follow_symlinks=False)
                opened = os.fstat(directory_fd)
                return (linked.st_dev, linked.st_ino) == (opened.st_dev, opened.st_ino)
    except (OSError, TypeError, ValueError, RecursionError):
        return False

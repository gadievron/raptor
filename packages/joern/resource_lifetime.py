"""Kernel-held resource lifetimes, independent of PID namespace numbering.

These locks are admission bookkeeping, not a memory or process security limit.
A JVM inherits its lock descriptor; its parent's exit cannot release the charge.
"""

from dataclasses import dataclass
import fcntl
import os
from pathlib import Path
import re
import stat


def _directory(ledger: Path, *, create=False):
    directory = ledger.with_name(ledger.name + ".leases")
    if create:
        directory.mkdir(mode=0o700, exist_ok=True)
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise OSError("unsafe Joern resource lifetime directory")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _name(identity):
    if not isinstance(identity, str) or re.fullmatch(r"[0-9a-f]{32}", identity) is None:
        raise OSError("invalid Joern resource lifetime identity")
    return identity + ".lock"


def held(ledger: Path, identity):
    """False proves no holder; an unverifiable lock remains charged."""
    try:
        directory = _directory(ledger)
        try:
            descriptor = os.open(_name(identity), os.O_RDWR | os.O_NONBLOCK | os.O_NOFOLLOW,
                                 dir_fd=directory)
        finally:
            os.close(directory)
    except FileNotFoundError:
        return False
    except OSError:
        return True
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or info.st_nlink != 1):
            return True
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return False
        except BlockingIOError:
            return True
        except OSError:
            return True
    finally:
        os.close(descriptor)


def discard(ledger: Path, identity):
    """Called under the ledger lock, after proving there are no holders."""
    if held(ledger, identity):
        return
    try:
        directory = _directory(ledger)
        try:
            os.unlink(_name(identity), dir_fd=directory)
        finally:
            os.close(directory)
    except FileNotFoundError:
        pass


@dataclass
class Lifetime:
    descriptor: int | None
    path: Path

    @classmethod
    def create(cls, ledger: Path, identity):
        directory = _directory(ledger, create=True)
        try:
            descriptor = os.open(_name(identity), os.O_RDONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=directory)
        finally:
            os.close(directory)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
            return cls(descriptor, ledger.with_name(ledger.name + ".leases") / _name(identity))
        except BaseException:
            os.close(descriptor)
            raise

    @property
    def pass_fds(self):
        return (self.descriptor,) if self.descriptor is not None else ()

    def close(self):
        descriptor, self.descriptor = self.descriptor, None
        if descriptor is not None:
            # Never LOCK_UN: a child shares this open-file description.
            os.close(descriptor)

    def __del__(self):
        self.close()

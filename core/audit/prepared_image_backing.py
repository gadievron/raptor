"""Unactivated supplied-artifact backing ownership, not a filesystem lease.

An expected digest names a NEW artifact. Copying it does not establish a
consistent snapshot of an old host tree. Seals protect retained bytes only;
filesystem interpretation, lookup closure and child consumption remain absent.
The production factory deliberately returns None. No descriptor is published.
"""
from dataclasses import dataclass, field
import hashlib
import math
import stat
from threading import RLock
import time


def _production_backing_backend():
    return None


def _linux_api():
    # Platform discovery is lazy; importing this module performs no OS operation.
    import os
    import sys
    if not sys.platform.startswith("linux"):
        raise OSError("unsupported backing platform")
    import fcntl
    for name in ("memfd_create", "MFD_CLOEXEC", "MFD_ALLOW_SEALING", "pread"):
        if not hasattr(os, name):
            raise OSError("unsupported backing API")
    for name in ("F_ADD_SEALS", "F_GET_SEALS", "F_SEAL_WRITE", "F_SEAL_GROW",
                 "F_SEAL_SHRINK", "F_SEAL_SEAL"):
        if not hasattr(fcntl, name):
            raise OSError("unsupported seal API")
    return os, fcntl


class _LinuxSeals:
    """Concrete backend source; not installed by the production factory."""

    def __init__(self):
        self.os, self.fcntl = _linux_api()
        f = self.fcntl
        self.required = f.F_SEAL_WRITE | f.F_SEAL_GROW | f.F_SEAL_SHRINK | f.F_SEAL_SEAL

    def create(self):
        return self.os.memfd_create("raptor-image-backing",
                                    self.os.MFD_CLOEXEC | self.os.MFD_ALLOW_SEALING)

    def private(self, fd):
        self.os.set_inheritable(fd, False)
        if self.os.get_inheritable(fd):
            raise OSError("inheritable backing")

    def info(self, fd):
        return self.os.fstat(fd)

    def read(self, fd, size, offset):
        return self.os.pread(fd, size, offset)

    def write(self, fd, data):
        return self.os.write(fd, data)

    def seal(self, fd):
        self.fcntl.fcntl(fd, self.fcntl.F_ADD_SEALS, self.required)

    def verify(self, fd):
        seals = self.fcntl.fcntl(fd, self.fcntl.F_GET_SEALS)
        if seals & self.required != self.required:
            raise OSError("incomplete backing seals")
        if self.os.get_inheritable(fd):
            raise OSError("inheritable backing")

    def close(self, fd):
        # Linux consumes the descriptor even on close errors: never retry a number.
        self.os.close(fd)


@dataclass(frozen=True)
class SuppliedArtifactIdentity:
    byte_count: int
    sha256: str


@dataclass(frozen=True)
class ImageBackingUnavailable:
    reason: str


@dataclass(frozen=True, eq=False)
class ImageBackingReference:
    pass


@dataclass(frozen=True)
class ImageBackingDescription:
    identity: SuppliedArtifactIdentity
    state: str = "retained_backing_bytes_only"
    authenticated_build: bool = field(default=False, init=False)
    observed_child_context: bool = field(default=False, init=False)


class _Unavailable(Exception):
    pass


class ImageBackingOwner:
    """Bounded private handles. Lifetime is checked on access, not by a reaper.

    The source descriptor is borrowed and must remain owned by the caller until
    acquire returns. Positional reads preserve its offset. Artifact byte limits
    do not bound Python RSS or kernel accounting overhead. Trusted parent Python
    can inspect private fields; this is not an adversarial in-process boundary.
    """

    def __init__(self, *, max_images, max_artifact_bytes, max_retained_bytes,
                 lifetime_seconds, max_read_bytes=0):
        for value in (max_images, max_artifact_bytes, max_retained_bytes):
            if type(value) is not int or value <= 0:
                raise ValueError("positive integer backing budgets required")
        if (type(lifetime_seconds) not in (int, float)
                or not math.isfinite(lifetime_seconds) or lifetime_seconds <= 0):
            raise ValueError("finite positive backing lifetime required")
        if type(max_read_bytes) is not int or max_read_bytes < 0:
            raise ValueError("nonnegative integer backing read budget required")
        self._limits = max_images, max_artifact_bytes, max_retained_bytes
        self._lifetime = lifetime_seconds
        # Explicit opt-in for a future private image interpreter; no FD handoff.
        self._read_bytes_remaining = max_read_bytes
        self._entries = {}
        self._closed = False
        self._poisoned = False
        self._busy = False
        self._lock = RLock()

    def _deadline_check(self, deadline):
        now = time.monotonic()
        if not math.isfinite(now) or now >= deadline:
            raise _Unavailable("backing lifetime exceeded")

    def _close_fd(self, backend, fd):
        try:
            backend.close(fd)
        except BaseException:
            self._poisoned = True
            raise

    def _drop(self, reference):
        if type(reference) is not ImageBackingReference:
            return
        entry = self._entries.pop(reference, None)
        if entry is not None:
            backend, fd, _, _ = entry
            self._close_fd(backend, fd)

    def _reap(self):
        now = time.monotonic()
        if not math.isfinite(now):
            raise _Unavailable("invalid backing clock")
        for reference, (_, _, _, deadline) in tuple(self._entries.items()):
            if now >= deadline:
                self._drop(reference)

    def _hash(self, backend, fd, identity, deadline):
        digest = hashlib.sha256()
        offset = 0
        while offset < identity.byte_count:
            self._deadline_check(deadline)
            data = backend.read(fd, min(65536, identity.byte_count - offset), offset)
            if type(data) is not bytes or not 0 < len(data) <= identity.byte_count - offset:
                raise _Unavailable("incomplete backing read")
            offset += len(data)
            digest.update(data)
        if backend.read(fd, 1, offset) != b"":
            raise _Unavailable("backing size changed")
        if digest.hexdigest() != identity.sha256:
            raise _Unavailable("artifact identity mismatch")

    def acquire(self, source_fd, identity):
        """Copy an explicitly supplied new artifact; no mount or lease issuance."""
        with self._lock:
            if self._busy:
                return ImageBackingUnavailable("backing owner re-entry")
            self._busy = True
            backend = None
            fd = None
            failure = None
            result = None
            try:
                if self._closed or self._poisoned:
                    raise _Unavailable("backing owner unavailable")
                self._reap()
                if (type(source_fd) is not int or source_fd < 0
                        or type(identity) is not SuppliedArtifactIdentity
                        or type(identity.byte_count) is not int or identity.byte_count <= 0
                        or type(identity.sha256) is not str or len(identity.sha256) != 64
                        or any(c not in "0123456789abcdef" for c in identity.sha256)):
                    raise _Unavailable("invalid artifact identity")
                count, per_image, retained = self._limits
                if (len(self._entries) >= count or identity.byte_count > per_image
                        or sum(e[2].byte_count for e in self._entries.values())
                        + identity.byte_count > retained):
                    raise _Unavailable("backing budget exceeded")
                now = time.monotonic()
                deadline = now + self._lifetime
                if not math.isfinite(now) or not math.isfinite(deadline):
                    raise _Unavailable("invalid backing clock")
                backend = _production_backing_backend()
                if backend is None:
                    raise _Unavailable("backing acquisition unavailable")
                info = backend.info(source_fd)
                if not stat.S_ISREG(info.st_mode) or info.st_size != identity.byte_count:
                    raise _Unavailable("unsupported artifact source")
                fd = backend.create()
                backend.private(fd)
                offset = 0
                while offset < identity.byte_count:
                    self._deadline_check(deadline)
                    data = backend.read(source_fd, min(65536, identity.byte_count - offset), offset)
                    if type(data) is not bytes or not 0 < len(data) <= identity.byte_count - offset:
                        raise _Unavailable("incomplete artifact copy")
                    written = 0
                    while written < len(data):
                        self._deadline_check(deadline)
                        n = backend.write(fd, data[written:])
                        if type(n) is not int or not 0 < n <= len(data) - written:
                            raise _Unavailable("incomplete artifact write")
                        written += n
                    offset += len(data)
                if backend.read(source_fd, 1, offset) != b"":
                    raise _Unavailable("artifact grew during copy")
                backend.seal(fd)
                backend.verify(fd)
                info = backend.info(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_size != identity.byte_count:
                    raise _Unavailable("backing size mismatch")
                self._hash(backend, fd, identity, deadline)
                backend.verify(fd)
                self._deadline_check(deadline)
                result = ImageBackingReference()
                self._entries[result] = backend, fd, identity, deadline
            except BaseException as exc:
                failure = exc
            finally:
                if failure is not None and fd is not None:
                    # Publication may have inserted before raising. Revoke that
                    # entry before closing the still-locally-owned descriptor.
                    if result is not None:
                        dict.pop(self._entries, result, None)
                    try:
                        self._close_fd(backend, fd)
                    except BaseException as exc:
                        if failure is None or (isinstance(failure, Exception)
                                               and not isinstance(exc, Exception)):
                            failure = exc
                self._busy = False
            if failure is not None:
                if not isinstance(failure, Exception):
                    raise failure
                return ImageBackingUnavailable(str(failure) if isinstance(failure, _Unavailable)
                                               else "backing acquisition failed")
            return result

    def describe(self, reference):
        with self._lock:
            if self._busy or self._closed or self._poisoned:
                return ImageBackingUnavailable("backing owner unavailable")
            self._busy = True
            try:
                self._reap()
                entry = (self._entries.get(reference)
                         if type(reference) is ImageBackingReference else None)
                if entry is None:
                    raise _Unavailable("foreign or retired backing")
                backend, fd, identity, deadline = entry
                backend.verify(fd)
                self._deadline_check(deadline)
                return ImageBackingDescription(identity)
            except BaseException as exc:
                try:
                    self._drop(reference)
                except BaseException as cleanup:
                    if isinstance(exc, Exception) and not isinstance(cleanup, Exception):
                        raise
                if not isinstance(exc, Exception):
                    raise
                return ImageBackingUnavailable("backing observation unavailable")
            finally:
                self._busy = False

    def _read(self, reference, offset, size):
        """Private bounded byte access, not a filesystem or child-use receipt.

        Disabled unless the owner has an explicit read budget. Each request is
        at most 64 KiB and charged before backend calls, including failed reads.
        No budget refund, descriptor exposure or retention-lifetime extension.
        """
        with self._lock:
            if self._busy or self._closed or self._poisoned:
                return ImageBackingUnavailable("backing owner unavailable")
            self._busy = True
            touched = False
            try:
                self._reap()
                entry = (self._entries.get(reference)
                         if type(reference) is ImageBackingReference else None)
                if entry is None:
                    raise _Unavailable("foreign or retired backing")
                backend, fd, identity, deadline = entry
                if (type(offset) is not int or offset < 0 or type(size) is not int
                        or not 0 < size <= 65536 or offset + size > identity.byte_count):
                    raise _Unavailable("invalid backing read range")
                if size > self._read_bytes_remaining:
                    raise _Unavailable("backing read budget exceeded")
                self._read_bytes_remaining -= size
                touched = True
                backend.verify(fd)
                self._deadline_check(deadline)
                content = bytearray()
                while len(content) < size:
                    self._deadline_check(deadline)
                    remaining = size - len(content)
                    data = backend.read(fd, remaining, offset + len(content))
                    if type(data) is not bytes or not 0 < len(data) <= remaining:
                        raise _Unavailable("incomplete backing read")
                    content.extend(data)
                result = bytes(content)
                backend.verify(fd)
                self._deadline_check(deadline)
                return result
            except BaseException as exc:
                if touched:
                    try:
                        self._drop(reference)
                    except BaseException as cleanup:
                        if isinstance(exc, Exception) and not isinstance(cleanup, Exception):
                            raise
                if not isinstance(exc, Exception):
                    raise
                return ImageBackingUnavailable("backing read unavailable")
            finally:
                self._busy = False

    def retire(self, reference):
        with self._lock:
            if self._busy:
                raise RuntimeError("backing owner re-entry")
            self._busy = True
            try:
                self._drop(reference)
            finally:
                self._busy = False

    def close(self):
        with self._lock:
            if self._busy:
                raise RuntimeError("backing owner re-entry")
            self._busy = True
            self._closed = True
            failure = None
            try:
                for reference in tuple(self._entries):
                    try:
                        self._drop(reference)
                    except BaseException as exc:
                        if failure is None or (isinstance(failure, Exception)
                                               and not isinstance(exc, Exception)):
                            failure = exc
                if failure is not None:
                    raise failure
            finally:
                self._busy = False

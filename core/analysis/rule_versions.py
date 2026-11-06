"""Optional tool requirements in trusted Coccinelle/CodeQL rule headers."""

import os
import re
import shutil
import threading
from collections.abc import Callable
from concurrent.futures import Future

_process_id = os.getpid


def version_tuple(value: str | None) -> tuple[int, int, int] | None:
    """Parse a stable release, permitting a tool's trailing build description."""
    if not value or len(value) > 1024:
        return None
    match = re.fullmatch(r"v?([0-9]{1,6})\.([0-9]{1,6})(?:\.([0-9]{1,6}))?(?:\s.*)?", value.strip())
    if not match:
        return None
    major, minor, patch = match.groups()
    return int(major), int(minor), int(patch or 0)


class VersionProbeCache:
    """Owner-local, single-entry cache of successful executable version facts.

    Concurrent checks of the same executable share one in-flight probe.
    Unknown answers remain retryable; no callback or report payload survives
    the call. Instantiate per sweep or runner, never as a global tool cache.
    """

    def __init__(self) -> None:
        self._reset()

    def _reset(self) -> None:
        self._lock = threading.Lock()
        self._key: tuple[object, ...] | None = None
        self._value: str | None = None
        self._pending: tuple[tuple[object, ...], Future[str | None]] | None = None
        self._pid = _process_id()

    @staticmethod
    def _identity(executable: str | None) -> tuple[object, ...] | None:
        if not executable:
            return None
        try:
            path = executable if os.path.isabs(executable) else shutil.which(executable)
            if path is None:
                return None
            path = os.path.abspath(path)
            resolved = os.path.realpath(path)
            stat = os.stat(resolved)
            return (path, resolved, stat.st_dev, stat.st_ino, stat.st_size,
                    stat.st_mtime_ns, stat.st_ctime_ns)
        except (OSError, ValueError, RuntimeError):
            return None

    def get(self, installed: Callable[[], str | None],
            executable: Callable[[], str | None]) -> str | None:
        # A forked child must not inherit a locked mutex or a future whose
        # probe can complete only in its parent process.
        if self._pid != _process_id():
            self._reset()
        key = self._identity(executable())
        if key is None:
            return installed()
        with self._lock:
            if key == self._key:
                return self._value
            if self._pending is not None and self._pending[0] == key:
                future = self._pending[1]
                owner = False
            else:
                future = Future()
                owner = True
                if self._pending is None:
                    self._pending = (key, future)
        if not owner:
            value = future.result()
            return value if self._identity(executable()) == key else None
        try:
            value = installed()
            if self._identity(executable()) != key:
                value = None
            valid = version_tuple(value) is not None
        except BaseException as exc:
            with self._lock:
                if self._pending is not None and self._pending[1] is future:
                    self._pending = None
            future.set_exception(exc)
            raise
        with self._lock:
            if valid:
                self._key, self._value = key, value
            if self._pending is not None and self._pending[1] is future:
                self._pending = None
        future.set_result(value)
        return value


def rule_version_refusal(text: str, installed: Callable[[], str | None]) -> str | None:
    """Return a per-rule skip reason; undeclared rules never probe the tool.

    The declaration is a single leading // comment, before executable rule
    content. Invalid or duplicate declarations refuse only the affected rule.
    """
    requirements = []
    for line in text.removeprefix("﻿").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if not stripped.startswith("//"):
            break
        comment = stripped[2:].strip()
        if comment.startswith("raptor-min-version:"):
            requirements.append(comment.removeprefix("raptor-min-version:").strip())
    if not requirements:
        return None
    if len(requirements) != 1:
        return "rule skipped: duplicate raptor-min-version declarations"
    requirement = requirements[0]
    if not re.fullmatch(r"[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}", requirement):
        return "rule skipped: invalid raptor-min-version (expected major.minor.patch)"
    minimum = version_tuple(requirement)
    actual = version_tuple(installed())
    if actual is None:
        return f"rule skipped: requires tool >= {requirement}; installed version unknown"
    if minimum is not None and actual < minimum:
        actual_text = ".".join(map(str, actual))
        return f"rule skipped: requires tool >= {requirement}; installed {actual_text}"
    return None

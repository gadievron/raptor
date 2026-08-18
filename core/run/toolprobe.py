"""External-tool probing — the one way to ask "is tool X here, and
which version?".

Consolidates the ``shutil.which`` + ``--version`` subprocess idiom
repeated across the tree. The copies had drifted on three axes this
module fixes once:

* **Environment**: several probes inherited the caller's full
  environment (semgrep, coccinelle, tool_readiness, the corpora
  toolchain recorder) instead of ``RaptorConfig.get_safe_env()`` —
  version probes exec real binaries, and env-injection vectors
  (``JAVA_TOOL_OPTIONS``, ``LD_PRELOAD``…) apply to them like any
  other subprocess. Probes here always use the safe env when
  ``core.config`` is importable.
* **TOCTOU**: some probes ``which()``-checked availability and then
  exec'd the BARE tool name, letting a PATH rewrite between check and
  exec swap the binary (the race packages/coccinelle/runner.py
  documents). Probes here exec the resolved absolute path.
* **Output access**: tools print versions to stdout or stderr
  (``java -version``!) — :attr:`ToolInfo.first_line` implements the
  common ``stdout-else-stderr`` first-line convention; the raw streams
  stay available for tool-specific parsing.

Argv is always list-based; nothing here goes near a shell.

The per-process cache exists for hot callers (per-finding probes) and
caches negative results too. It is OPT-IN per call site: callers whose
tests patch ``subprocess.run`` per-test (the norm for version()
surfaces) pass ``use_cache=False`` and stay hermetic without knowing
about this module's state. :func:`reset_probe_cache` is the test hook.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import threading
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

__all__ = ["ToolInfo", "probe", "reset_probe_cache"]

_VERSION_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")

_CACHE_LOCK = threading.Lock()
_CACHE: dict[tuple[str, tuple[str, ...]], ToolInfo | None] = {}


@dataclass(frozen=True)
class ToolInfo:
    """Result of one tool probe.

    ``returncode is None`` means the probe subprocess itself failed
    (timeout / exec error) — the tool exists on PATH but did not
    answer. A missing tool is represented by :func:`probe` returning
    ``None``, not by a ``ToolInfo``.
    """

    name: str
    path: str
    args: tuple[str, ...] = ("--version",)
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    # Not part of identity/comparison; carried for diagnostics.
    error: str = field(default="", compare=False)

    @property
    def first_line(self) -> str | None:
        """First line of stdout-else-stderr (the convention most
        version probes implement by hand), or ``None`` when the tool
        produced no output."""
        out = (self.stdout or self.stderr or "").strip()
        return out.splitlines()[0] if out else None

    def version_tuple(self) -> tuple[int, ...] | None:
        """Best-effort ``(major, minor[, patch])`` ints from the first
        version-looking token in :attr:`first_line`, or ``None``."""
        line = self.first_line
        if not line:
            return None
        m = _VERSION_RE.search(line)
        if not m:
            return None
        return tuple(int(g) for g in m.groups() if g is not None)


def _safe_env() -> dict | None:
    """Sanitised env for the probe; ``None`` (inherit) only when
    core.config is unimportable (early-bootstrap callers)."""
    try:
        from core.config import RaptorConfig
    except ImportError:
        return None
    return RaptorConfig.get_safe_env()


def probe(
    name: str,
    *,
    args: tuple[str, ...] = ("--version",),
    timeout: float = 10,
    use_cache: bool = False,
) -> ToolInfo | None:
    """Locate *name* on PATH and run it with *args*.

    Returns ``None`` when the tool is not on PATH. Otherwise returns a
    :class:`ToolInfo`; a probe-execution failure (timeout, exec error)
    yields ``returncode=None`` with empty streams rather than raising.

    ``use_cache=True`` memoises per ``(name, args)`` — including the
    not-on-PATH result — for hot call sites; leave it off where tests
    patch ``shutil.which`` / ``subprocess.run`` per-test.
    """
    key = (name, args)
    if use_cache:
        with _CACHE_LOCK:
            if key in _CACHE:
                return _CACHE[key]
    path = shutil.which(name)
    if path is None:
        info: ToolInfo | None = None
    else:
        try:
            proc = subprocess.run(
                [path, *args],
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout,
                env=_safe_env(),
            )
            info = ToolInfo(
                name=name, path=path, args=args,
                returncode=proc.returncode,
                stdout=proc.stdout or "",
                stderr=proc.stderr or "",
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            logger.debug("toolprobe: %s %s failed: %s", name, args, exc)
            info = ToolInfo(
                name=name, path=path, args=args,
                returncode=None,
                error=f"{type(exc).__name__}: {exc}",
            )
    if use_cache:
        with _CACHE_LOCK:
            _CACHE[key] = info
    return info


def reset_probe_cache() -> None:
    """Clear the probe cache (test hook)."""
    with _CACHE_LOCK:
        _CACHE.clear()

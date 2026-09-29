"""Availability probes for the heavy dependencies core.symbolic uses.

Every primitive in this package that needs angr / claripy
should call the relevant ``*_available()`` at entry and return a
descriptive :class:`SymbolicResult` when the dep is missing, rather
than raising ImportError. Callers (the LLM tool wrappers) can then
present a clean "capability unavailable" signal instead of a
Python traceback.

Each probe attempts the import in a DISPOSABLE CHILD process, never
in-process: angr's import chain reaches pypcode_native's C++ init,
which can abort the host uncatchably (SIGABRT) in state-heavy
processes — Python cannot catch a signal raised inside a C
extension's init, so an in-process probe puts the whole run (or an
xdist worker set) on the line. The child's fate maps to the bool:
clean exit means available; nonzero exit, death by signal, or
timeout means unavailable.

Cheap by design — one child per probe name, cached per process.
Probe failures are logged once at debug level; subsequent calls
return the cached bool without re-attempting.
"""
from __future__ import annotations

import logging
import os
import subprocess
import sys
import tempfile
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.symbolic._types import SymbolicResult

log = logging.getLogger(__name__)

_cache: dict[str, bool] = {}

#: Fixed program text for the probe child. The probed module name
#: rides as argv data (``sys.argv[1]``) — it is never interpolated
#: into program text, and every production caller passes one of this
#: file's own string constants ("angr", "z3", "claripy").
_CHILD_PROBE_SOURCE: str = (
    "import importlib, sys; importlib.import_module(sys.argv[1])"
)

#: Probe-child deadline, seconds. Lower risks a false "unavailable":
#: a cold angr import legitimately takes tens of seconds (pyvex
#: regenerates its ffi-parser cache on first import; loaded hosts run
#: probes under xdist contention), and a wrong False is memoized for
#: the whole run — every symbolic primitive would silently degrade.
#: Higher only delays surfacing a genuinely hung import (the very
#: hazard this bounds): the run's first gated primitive would stall
#: for the full bound before the clean False lands.
_PROBE_TIMEOUT_S: float = 120.0

#: Bound on the child-stderr excerpt kept for the debug log.
_STDERR_EXCERPT_CHARS: int = 500


def _import_probe_child(name: str, module: str) -> bool:
    """Attempt ``import module`` in a disposable child interpreter.

    Returns True only on a clean exit. A nonzero exit, death by
    signal (negative returncode — e.g. -6 for the pypcode_native
    SIGABRT), a hung import (timeout), or a spawn failure all read
    as unavailable; none of them can take the calling process down.
    """
    env: dict[str, str] = dict(os.environ)
    # Propagate this process's EFFECTIVE temp dir: under the symex
    # sandbox (core.symbolic._isolate) the parent pins
    # ``tempfile.tempdir`` to its private Landlock write grant, and
    # an in-process pin does not cross exec on its own. pyvex writes
    # its ffi-parser cache to the temp dir at import time, so a
    # probe child that fell back to the (write-denied) shared temp
    # dir would misreport angr as unavailable inside the sandbox.
    env["TMPDIR"] = tempfile.gettempdir()
    cmd: list[str] = [sys.executable, "-c", _CHILD_PROBE_SOURCE, module]
    try:
        # All three stdio channels are pipes, never subprocess.DEVNULL:
        # DEVNULL opens /dev/null O_RDWR — a write-open, which the
        # symex sandbox's Landlock ruleset (core.symbolic._isolate)
        # denies outside the child's private temp grant. This probe
        # runs inside those sandboxed children (availability_gate),
        # so its plumbing must carry no filesystem access at all.
        # ``input=b""`` gives the child an immediately-closed stdin.
        proc = subprocess.run(
            cmd,
            input=b"",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            timeout=_PROBE_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        log.debug(
            "core.symbolic dep %s unavailable: import probe exceeded "
            "%.0fs", name, _PROBE_TIMEOUT_S,
        )
        return False
    except OSError as exc:
        log.debug(
            "core.symbolic dep %s unavailable: probe spawn failed: %s",
            name, exc,
        )
        return False
    if proc.returncode == 0:
        return True
    stderr_tail = proc.stderr.decode("utf-8", errors="replace")
    stderr_tail = stderr_tail[-_STDERR_EXCERPT_CHARS:].strip()
    log.debug(
        "core.symbolic dep %s unavailable: probe exit %d: %s",
        name, proc.returncode, stderr_tail,
    )
    return False


def _probe(name: str, module: str) -> bool:
    if name in _cache:
        return _cache[name]
    if module == "angr":
        # Pre-set the noisy import-time logger: angr logs an ERROR
        # when optional acceleration (unicornlib) is missing —
        # operator noise, not a result channel. Logger config is
        # name-based, so setting it here lands before this process's
        # first real ``import angr`` (every angr consumer gates on
        # this probe first); the probe child's own copy of that noise
        # stays on the child's captured stderr.
        import logging as _logging
        _logging.getLogger(
            "angr.state_plugins.unicorn_engine").setLevel(
            _logging.CRITICAL)
    _cache[name] = _import_probe_child(name, module)
    return _cache[name]


def angr_available() -> bool:
    """True when angr can be imported. Angr is the heaviest optional
    dep — CFG / symex / claripy. Primitives that need angr must
    check this first."""
    return _probe("angr", "angr")


def z3_available() -> bool:
    """True when Z3 (via claripy or direct) can be imported. Some
    primitives can degrade to Z3-only paths when angr is absent —
    e.g. constraint solving over a caller-supplied SMT formula
    doesn't need binary execution.

    Note: angr always pulls z3 via claripy, so ``z3_available()``
    should return True whenever ``angr_available()`` does. It can
    also return True when angr is missing but the standalone
    ``z3-solver`` package is installed for :mod:`core.smt_solver`.
    """
    return _probe("z3", "z3") or _probe("claripy", "claripy")




def clear_probe_cache() -> None:
    """Reset the availability cache. Test-only helper — production
    code should never need this."""
    _cache.clear()


def unavailable_result(dep: str, primitive: str) -> "SymbolicResult":
    """Uniform SymbolicResult for a primitive that can't run because
    its underlying dep isn't installed. Keeps the LLM tool surface
    consistent: same tool always registered; a clean 'unavailable'
    result on invocation rather than a Python traceback.
    """
    from core.symbolic._types import SymbolicResult
    return SymbolicResult(
        succeeded=False,
        reason=(
            f"{primitive} requires {dep}; not available on this "
            "install. Install the dep (e.g. `pip install "
            f"{dep}`) or use an alternate primitive."
        ),
        wall_seconds=0.0,
        metadata={"unavailable_dep": dep, "primitive": primitive},
    )

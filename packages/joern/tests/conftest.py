"""Shared joern test isolation and suite-wide guards.

The heap ledger arbitrates JVM spawns through a HOST-GLOBAL file
under the user's home. Tests must never read or write that file:
a test row would clamp a concurrently-running real analysis (and a
real run's committed heap would flip test grant assertions), and the
grant math must not depend on the CI runner's physical RAM — a
test asserting ``-J-Xmx16384m`` in a spawn argv would fail on any
runner with less RAM than the asserted heap.

Tripwire: no test may leave a ``JoernServer`` handle aimed at a
sentinel pid/pgid (≤ 1) alive. ``JoernServer.__del__`` runs the REAL
``stop()`` at GC time — after the test's monkeypatches are undone —
and ``killpg(1, sig)`` is ``kill(-1, sig)`` at the kernel: a broadcast
to every process this uid can signal. A fabricated handle with
``_pgid = 1`` did exactly that once, SIGTERMing every same-uid
process on the host each time the file ran. The product guards now
refuse pgid ≤ 1, but the suite must never rely on them: any offender
is defused in place (so its eventual finalizer is a no-op even on a
regressed tree) and the test that built it fails by name.

The same sweep silently defuses every leaked server whose ``_proc``
is a test double rather than a real ``subprocess.Popen``. Doubles
routinely outlive their test inside reference cycles (a MagicMock
proc alone is one), so their destruction waits for the cyclic
collector — which can run inside a LATER test's ``patch`` window,
where the deferred ``__del__ -> stop()`` replays against that test's
mocks (a phantom ``_ensure_group_dead`` call was the observed shape).
Real-process handles keep their finalizer: for those, GC-time
``stop()`` is live cleanup, not replay.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import weakref
from pathlib import Path
from typing import Iterator

import pytest

from packages.joern import heap_ledger
from packages.joern.server import JoernServer


@pytest.fixture(autouse=True)
def _isolated_heap_ledger(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        heap_ledger, "_LEDGER_PATH", tmp_path / "heap-ledger.json",
    )
    # Effectively-unbounded budget: ledger-specific tests that
    # exercise clamping monkeypatch their own explicit budget.
    monkeypatch.setattr(
        heap_ledger, "_host_budget_mb", lambda: 1 << 24,
    )


# Longest socket filename any test binds inside ``uds_dir``; the
# fixture's path-budget assertion is computed against it.
_UDS_SOCK_NAME_MAX: int = len("joern.sock")
# Linux sun_path is 108 bytes including the trailing NUL, so bind()
# refuses paths longer than 107 characters.
_SUN_PATH_MAX: int = 107


def _uds_budget_ok(root: str) -> bool:
    """Worst-case socket path under a ``mkdtemp(prefix="j")`` child of
    *root* fits AF_UNIX's sun_path (mkdtemp appends 8 random chars)."""
    worst = os.path.join(root, "j" + "X" * 8, "n" * _UDS_SOCK_NAME_MAX)
    return len(worst) <= _SUN_PATH_MAX


@pytest.fixture
def uds_dir() -> Iterator[str]:
    """Deterministically short 0700 directory for AF_UNIX socket binds.

    Deliberately NOT pytest's ``tmp_path``: that nests
    ``$TMPDIR/pytest-of-<user>/pytest-<N>/popen-gw<K>/<testname>N/``
    and a socket path built inside it can exceed sun_path, so
    ``bind()`` errors before the behaviour under test runs (the
    ``popen-gw<K>`` worker segment makes this xdist-dependent).

    Length budget, both directions:

    * why not longer — sun_path caps the WHOLE path at 107 chars
      (108 bytes with the NUL); every byte of directory nesting is
      spent against that fixed ceiling, so the fixture creates its
      dir directly under the TMPDIR root with a one-char prefix and
      asserts the worst-case socket filename still fits;
    * why not shorter / why not always ``/tmp`` — namespaced battery
      runs give each run a private TMPDIR for isolation, and ``/tmp``
      is shared across sessions; the fixture honours TMPDIR and only
      falls back to ``/tmp`` when the TMPDIR root itself is already
      too long for any socket path beneath it.
    """
    root = tempfile.gettempdir()
    if not _uds_budget_ok(root):
        root = "/tmp"
    assert _uds_budget_ok(root), (
        f"even {root!r} cannot host an AF_UNIX socket path"
    )
    d = tempfile.mkdtemp(prefix="j", dir=root)  # 0700 by default
    assert len(d) + 1 + _UDS_SOCK_NAME_MAX <= _SUN_PATH_MAX
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _sentinel(value: object) -> bool:
    """True when *value* is an int ≤ 1 (a broadcast-capable pgid/pid)."""
    return isinstance(value, int) and not isinstance(value, bool) and value <= 1


# Every JoernServer constructed in this process, alive or awaiting
# collection. The per-test sweep inspects THIS set: sweeping the
# whole heap instead (gc.get_objects() + isinstance over millions of
# tracked objects) costs most of a second per call, and as an
# autouse teardown that single line dominated the suite's runtime
# (~0.75s x ~880 tests measured under the nightly tier).
_LIVE_SERVERS: "weakref.WeakSet[JoernServer]" = weakref.WeakSet()


@pytest.fixture(scope="session", autouse=True)
def _track_server_handles() -> Iterator[None]:
    """Register every JoernServer construction in ``_LIVE_SERVERS``.

    ``__new__`` is the hook, not ``__init__``: the doubles the sweep
    exists to catch are built with ``JoernServer.__new__(JoernServer)``
    and never run ``__init__``. The weak references keep sweep
    visibility without extending any handle's lifetime — a handle
    collected mid-test already ran its finalizer inside that test's
    own patch window, which is the pre-sweep status quo.
    """
    def tracking_new(cls: type, *args: object, **kwargs: object) -> JoernServer:
        obj = object.__new__(cls)
        _LIVE_SERVERS.add(obj)
        return obj

    JoernServer.__new__ = tracking_new  # type: ignore[method-assign]
    try:
        yield
    finally:
        del JoernServer.__new__
        _LIVE_SERVERS.clear()


@pytest.fixture(autouse=True)
def _no_sentinel_server_handles(
    request: pytest.FixtureRequest,
    _track_server_handles: None,
) -> Iterator[None]:
    yield
    offenders: list[str] = []
    for obj in list(_LIVE_SERVERS):
        pgid = getattr(obj, "_pgid", None)
        proc = getattr(obj, "_proc", None)
        try:
            pid = getattr(proc, "pid", None)
        except Exception:  # noqa: BLE001 — hostile test doubles
            pid = None
        if _sentinel(pgid) or _sentinel(pid):
            offenders.append(
                f"JoernServer at 0x{id(obj):x} with _pgid={pgid!r}, "
                f"_proc.pid={pid!r}"
            )
            # Defuse BEFORE failing: the finalizer early-returns on a
            # None _proc, so this handle can never signal anything.
            obj._proc = None
            obj._pgid = None
        elif proc is not None and not isinstance(proc, subprocess.Popen):
            # Double-backed leak: its deferred __del__ -> stop() would
            # replay against a later test's patched mocks (see module
            # docstring). Defuse silently — stopping a double at GC
            # time cleans up nothing real by definition.
            obj._proc = None
            obj._pgid = None
    if offenders:
        pytest.fail(
            f"{request.node.nodeid} left live JoernServer handle(s) "
            "aimed at a sentinel pid/pgid (killpg(1, sig) is a same-uid "
            "kill(-1, sig) broadcast at GC time): " + "; ".join(offenders)
        )

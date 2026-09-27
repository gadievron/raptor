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
"""

from __future__ import annotations

import gc
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


def _sentinel(value: object) -> bool:
    """True when *value* is an int ≤ 1 (a broadcast-capable pgid/pid)."""
    return isinstance(value, int) and not isinstance(value, bool) and value <= 1


@pytest.fixture(autouse=True)
def _no_sentinel_server_handles(request: pytest.FixtureRequest) -> Iterator[None]:
    yield
    offenders: list[str] = []
    for obj in gc.get_objects():
        if not isinstance(obj, JoernServer):
            continue
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
    if offenders:
        pytest.fail(
            f"{request.node.nodeid} left live JoernServer handle(s) "
            "aimed at a sentinel pid/pgid (killpg(1, sig) is a same-uid "
            "kill(-1, sig) broadcast at GC time): " + "; ".join(offenders)
        )

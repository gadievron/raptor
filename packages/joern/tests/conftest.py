"""Shared joern test isolation.

The heap ledger arbitrates JVM spawns through a HOST-GLOBAL file
under the user's home. Tests must never read or write that file:
a test row would clamp a concurrently-running real analysis (and a
real run's committed heap would flip test grant assertions), and the
grant math must not depend on the CI runner's physical RAM — a
test asserting ``-J-Xmx16384m`` in a spawn argv would fail on any
runner with less RAM than the asserted heap.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from packages.joern import heap_ledger


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

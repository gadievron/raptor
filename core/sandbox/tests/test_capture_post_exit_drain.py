"""A finished run must not stay pinned to sibling capture-pipe copies.

The capture loop used to run until BOTH out/err pipes hit EOF and only
then waitpid the child. Concurrent spawns transiently retain inherited
copies of each other's write ends, so an instant ``echo`` run's return
was pinned to a sibling's full lifetime (~12s observed) — and with a
shorter caller timeout the pinned run raised TimeoutExpired even
though its target had already exited 0: a wrong verdict under
concurrency. The loop now reap-polls the child and, once it has
exited, drains for a BOUNDED window (``_POST_EXIT_DRAIN_SECONDS``)
instead of waiting for an EOF governed by unrelated processes.

The retention is simulated deterministically here by duping the
capture write ends into the test process at creation time.
"""

from __future__ import annotations

import sys as _sys

import pytest as _pytest

pytestmark = _pytest.mark.skipif(
    _sys.platform != "linux",
    reason="Linux-only sandbox internals",
)

import os  # noqa: E402
import time  # noqa: E402


@_pytest.fixture
def retained_write_ends(monkeypatch):
    """Dup every capture write end into this (holder) process."""
    from core.sandbox import _spawn

    holders: list[int] = []
    real = _spawn._open_capture_pipes

    def retaining() -> tuple[int, int, int, int]:
        out_r, out_w, err_r, err_w = real()
        holders.append(os.dup(out_w))
        holders.append(os.dup(err_w))
        return out_r, out_w, err_r, err_w

    monkeypatch.setattr(_spawn, "_open_capture_pipes", retaining)
    yield holders
    for fd in holders:
        try:
            os.close(fd)
        except OSError:
            pass


def _userns_available() -> bool:
    from core.sandbox import check_net_available
    try:
        return bool(check_net_available())
    except Exception:  # noqa: BLE001 — capability probe only
        return False


@_pytest.mark.skipif(
    not _userns_available(), reason="user namespaces unavailable",
)
def test_exited_child_not_pinned_by_retained_write_ends(
    retained_write_ends,
):
    from core.sandbox import run as sandbox_run
    from core.sandbox import _spawn

    t0 = time.monotonic()
    result = sandbox_run(
        ["echo", "hi"], block_network=True,
        capture_output=True, text=True, timeout=30,
    )
    elapsed = time.monotonic() - t0
    assert retained_write_ends, "retention simulation never engaged"
    assert result.returncode == 0
    assert "hi" in result.stdout
    # Bounded by spawn overhead + the drain window, never by the
    # 30s deadline the EOF wait used to ride to (generous 10x slack
    # over the 0.5s window for loaded CI).
    assert elapsed < 15.0, (
        f"return took {elapsed:.1f}s — still pinned to retained "
        f"sibling write ends"
    )
    assert _spawn._POST_EXIT_DRAIN_SECONDS < 5.0  # window stays bounded


@_pytest.mark.skipif(
    not _userns_available(), reason="user namespaces unavailable",
)
def test_exited_child_never_misreported_as_timeout(retained_write_ends):
    # The wrong-verdict direction: a caller timeout longer than the
    # run but shorter than the sibling's retention must NOT surface
    # as TimeoutExpired for a target that exited 0. (Pre-fix the
    # capture loop rode the EOF wait into the deadline and raised.)
    from core.sandbox import run as sandbox_run

    result = sandbox_run(
        ["echo", "verdict"], block_network=True,
        capture_output=True, text=True, timeout=8,
    )
    assert result.returncode == 0
    assert "verdict" in result.stdout

"""Pool teardown must actually kill process-pool workers.

The trap pinned here: ``ProcessPoolExecutor.shutdown()`` clears its
``_processes`` map before returning, so a teardown that snapshots the
map AFTER shutdown terminates nothing — the wedged worker leaks,
holding the process's inherited stdout/stderr and blocking the
executor manager thread's join at interpreter exit (the process then
never exits and its output pipe never closes). The snapshot must be
taken first, and SIGTERM must escalate to SIGKILL: fork-context
workers inherit the parent's SIGTERM handler, and a handler that
blocks makes the worker survive ``terminate()`` indefinitely.
"""

from __future__ import annotations

import multiprocessing
import os
import signal
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from pathlib import Path
from types import FrameType

import pytest

from core.inventory.builder import (
    _init_inventory_worker,
    _shutdown_pool_nowait,
)

pytestmark = pytest.mark.skipif(
    not hasattr(os, "fork"),
    reason="fork start method required (deterministic handler "
           "inheritance)",
)


@pytest.fixture(autouse=True)
def _spawn_children_can_import_repo(monkeypatch):
    """Pin the repo root FIRST on the import path for spawn children.

    Spawn-context workers inherit the parent's sys.path snapshot
    (multiprocessing's preparation data; PYTHONPATH alone does not
    reach them) and re-import this module to unpickle the submitted
    callables. Under a parallel runner the parent's path is
    worker-order dependent — a relative entry rewritten against
    another test's cwd can put a shadowing ``core`` package ahead of
    the repo's, and the child then dies mid-unpickle with
    ``No module named 'core.inventory'`` — BrokenProcessPool in the
    happy-path test, nothing to do with the teardown behavior under
    pin. Prepending the absolute repo root makes the child's
    resolution first-match-deterministic. (Test-layer setup; the
    runtime path-safety rule does not apply to test files.)"""
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[3]))


def _wedge(sentinel: str = "") -> None:
    if sentinel:
        Path(sentinel).touch()
    time.sleep(600)


def _submit_wedge_started(pool: ProcessPoolExecutor, tmp_path: Path) -> None:
    """Submit the wedge task and wait — deadline-polled, never a fixed
    sleep — until the worker has STARTED it. The SIGTERM-timing
    assertions need the worker inside the task body (initializer done,
    handler/mask state installed); the fixed 0.5s sleep this replaces
    was the file's one sleep-based sync and flaked on starved runners
    (teardown raced the worker bootstrap, so a SIGTERM-immune worker
    died to plain SIGTERM instead of the asserted SIGKILL escalation).
    """
    sentinel = tmp_path / "wedge-task-started"
    pool.submit(_wedge, str(sentinel))
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        if sentinel.exists():
            return
        time.sleep(0.01)
    raise AssertionError("worker never started the wedge task")


def _blocking_handler(signum: int, frame: FrameType | None) -> None:
    # Deterministic stand-in for the fork-frozen-lock class: an
    # inherited handler that never returns, so SIGTERM never kills.
    time.sleep(600)


def _install_blocking_sigterm() -> None:
    signal.signal(signal.SIGTERM, _blocking_handler)


def _wait_dead(procs: list, timeout_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if not any(p.is_alive() for p in procs):
            return True
        time.sleep(0.05)
    return False


def test_teardown_kills_sigterm_immune_worker_via_sigkill(tmp_path: Path) -> None:
    """A worker whose inherited SIGTERM handler blocks must still die:
    the teardown escalates to SIGKILL after its grace window."""
    ctx = multiprocessing.get_context("fork")
    pool = ProcessPoolExecutor(
        max_workers=1, mp_context=ctx,
        initializer=_install_blocking_sigterm,
    )
    procs: list = []
    try:
        _submit_wedge_started(pool, tmp_path)
        procs = list(pool._processes.values())
        assert procs, "worker never spawned"
        t0 = time.monotonic()
        _shutdown_pool_nowait(pool, kill_grace_s=1.0)
        assert time.monotonic() - t0 < 15.0
        assert _wait_dead(procs, 10.0), (
            "SIGTERM-immune worker survived teardown"
        )
        assert procs[0].exitcode == -signal.SIGKILL
    finally:
        for p in procs:  # leak-guard for assertion failures above
            if p.is_alive():
                p.kill()


# Nightly tier: the test's COST is grace-bound by design — a passing
# run is sub-second (sentinel early-exit), but any regression or a
# genuinely starved runner burns the injected 10s grace before the
# verdict, past the default tier's RAPTOR_MAX_TEST_SECONDS budget.
# Trade-off: a regression here surfaces nightly, not per-PR — accepted
# because the same died-by-SIGTERM-promptly contract is pinned
# default-tier by test_production_worker_sheds_inherited_salvage_handler
# and test_production_worker_unblocks_inherited_sigterm_mask (identical
# assertion, adversarial parent state).
@pytest.mark.slow
def test_teardown_lets_responsive_worker_die_on_sigterm(tmp_path: Path) -> None:
    """A production-shaped worker dies to terminate() — no gratuitous
    SIGKILL inside the grace window.

    The pool is built the way builder.py builds it (with the
    initializer that resets the inherited SIGTERM disposition and
    mask). A RAW pool made this test depend on whatever SIGTERM state
    earlier tests left in this process: an orchestrator salvage
    handler leaked by an audit test ran in the fork child, ate the
    SIGTERM for longer than the grace, and the escalation SIGKILLed a
    perfectly responsive worker (exitcode -9 after the full grace on
    every run sharing that worker process)."""
    ctx = multiprocessing.get_context("fork")
    pool = ProcessPoolExecutor(
        max_workers=1, mp_context=ctx,
        initializer=_init_inventory_worker, initargs=_INIT_ARGS,
    )
    procs: list = []
    try:
        _submit_wedge_started(pool, tmp_path)
        procs = list(pool._processes.values())
        assert procs, "worker never spawned"
        _shutdown_pool_nowait(pool, kill_grace_s=10.0)
        assert _wait_dead(procs, 10.0)
        assert procs[0].exitcode == -signal.SIGTERM
    finally:
        for p in procs:  # leak-guard for assertion failures above
            if p.is_alive():
                p.kill()


def _salvage_shaped_handler(signum: int, frame: FrameType | None) -> None:
    # Shape of a leaked graceful-shutdown handler: consumes SIGTERM
    # and keeps running instead of dying.
    time.sleep(600)


def test_production_worker_sheds_inherited_salvage_handler(tmp_path: Path) -> None:
    """Deterministic replay of the observed poisoning: the parent
    carries a salvage-shaped SIGTERM handler at fork; a
    production-initialized worker must still die BY SIGTERM, fast —
    the initializer's disposition reset is the seatbelt."""
    prior = signal.getsignal(signal.SIGTERM)
    ctx = multiprocessing.get_context("fork")
    procs: list = []
    try:
        signal.signal(signal.SIGTERM, _salvage_shaped_handler)
        pool = ProcessPoolExecutor(
            max_workers=1, mp_context=ctx,
            initializer=_init_inventory_worker, initargs=_INIT_ARGS,
        )
        _submit_wedge_started(pool, tmp_path)
        procs = list(pool._processes.values())
        assert procs, "worker never spawned"
        _shutdown_pool_nowait(pool, kill_grace_s=10.0)
        assert _wait_dead(procs, 10.0)
        assert procs[0].exitcode == -signal.SIGTERM
    finally:
        signal.signal(signal.SIGTERM, prior)
        for p in procs:  # leak-guard for assertion failures above
            if p.is_alive():
                p.kill()


def test_production_worker_unblocks_inherited_sigterm_mask(tmp_path: Path) -> None:
    """The sibling hole: the MASK is inherited separately from the
    disposition — SIGTERM blocked in the forking thread leaves the
    signal pending-forever in the child even with SIG_DFL. The
    initializer must unblock it."""
    prior_mask = signal.pthread_sigmask(signal.SIG_BLOCK,
                                        {signal.SIGTERM})
    ctx = multiprocessing.get_context("fork")
    procs: list = []
    try:
        pool = ProcessPoolExecutor(
            max_workers=1, mp_context=ctx,
            initializer=_init_inventory_worker, initargs=_INIT_ARGS,
        )
        _submit_wedge_started(pool, tmp_path)
        procs = list(pool._processes.values())
        assert procs, "worker never spawned"
        _shutdown_pool_nowait(pool, kill_grace_s=10.0)
        assert _wait_dead(procs, 10.0)
        assert procs[0].exitcode == -signal.SIGTERM
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, prior_mask)
        for p in procs:  # leak-guard for assertion failures above
            if p.is_alive():
                p.kill()


# Nightly tier: grace-bound cost like the responsive test above (a
# broken snapshot order burns the 5s grace + the dead-wait before
# failing). Trade-off: nightly-only surfacing is accepted because the
# snapshot-order regression cannot pass the default tier unnoticed —
# test_teardown_kills_sigterm_immune_worker_via_sigkill drives the
# same helper end-to-end and its worker only dies at all when the
# snapshot preceded shutdown().
@pytest.mark.slow
def test_teardown_snapshot_precedes_shutdown(tmp_path: Path) -> None:
    """The regression itself: shutdown() nulls ``_processes``, so a
    post-shutdown snapshot sees nothing to kill and a plainly wedged
    worker leaks. The helper must reap it regardless.

    Production initializer so the worker's SIGTERM state is the
    test's own — with a raw pool, an inherited handler makes the
    reap burn the full grace before SIGKILL (slow, and it masks the
    prompt-SIGTERM path this file pins elsewhere)."""
    ctx = multiprocessing.get_context("fork")
    pool = ProcessPoolExecutor(
        max_workers=1, mp_context=ctx,
        initializer=_init_inventory_worker, initargs=_INIT_ARGS,
    )
    procs: list = []
    try:
        _submit_wedge_started(pool, tmp_path)
        procs = list(pool._processes.values())
        assert procs
        _shutdown_pool_nowait(pool, kill_grace_s=5.0)
        # shutdown() has dropped the executor's own reference…
        assert getattr(pool, "_processes", None) in (None, {})
        # …but the worker still died, because the snapshot came first.
        assert _wait_dead(procs, 10.0), "wedged worker leaked"
    finally:
        for p in procs:  # leak-guard for assertion failures above
            if p.is_alive():
                p.kill()


def test_teardown_no_ops_on_thread_pool() -> None:
    pool = ThreadPoolExecutor(max_workers=1)
    pool.submit(lambda: None).result(timeout=30)
    _shutdown_pool_nowait(pool)  # must not raise


def _report_sigterm_is_default() -> bool:
    return signal.getsignal(signal.SIGTERM) is signal.SIG_DFL


def _square(x: int) -> int:
    return x * x


_INIT_ARGS = (Path("."), [], True, {}, False, None, None, None)


def _install_exit_wedge() -> None:
    # Production-shaped worker first (SIGTERM disposition/mask reset,
    # stdio detach): the wedge under test is the EXIT path, not
    # signal state inherited from whatever ran earlier in this
    # process.
    _init_inventory_worker(*_INIT_ARGS)
    # Worker wedges on its EXIT path, after delivering every result:
    # multiprocessing children run registered Finalize callbacks in
    # _bootstrap's util._exit_function (module-level atexit hooks do
    # NOT run in mp children — Finalize is the one that does).
    from multiprocessing.util import Finalize
    Finalize(None, time.sleep, args=(600,), exitpriority=100)


def test_clean_shutdown_prompt_exit_no_escalation(caplog) -> None:
    """Happy path: workers that exit promptly off the shutdown
    sentinel are never signalled and no warning is emitted.

    Spawn context deliberately: this direction asserts NO escalation,
    and a fork child of the (threaded) pytest process can wedge on a
    fork-frozen lock at exit at a low baseline rate — the very class
    the helper defends against — which would flake these assertions.
    Spawn children start from a fresh interpreter and cannot inherit
    a frozen lock, so their prompt exit is deterministic. The helper
    is context-agnostic; the fork direction is covered by the
    escalation test below.
    """
    import logging

    from core.inventory.builder import _shutdown_pool_clean, logger

    ctx = multiprocessing.get_context("spawn")
    pool = ProcessPoolExecutor(max_workers=2, mp_context=ctx)
    procs: list = []
    try:
        futs = [pool.submit(_square, i) for i in range(8)]
        # Capture BEFORE resolving: a failure below must still leave
        # the leak-guard something to kill (a failing test must not
        # convert into an unbounded stall — the whole point here).
        procs = list(pool._processes.values())
        assert procs
        results = [f.result(timeout=60) for f in futs]
        assert results == [i * i for i in range(8)]
        with caplog.at_level(logging.WARNING, logger=logger.name):
            _shutdown_pool_clean(pool, grace_s=30.0)
        assert _wait_dead(procs, 10.0)
        # exitcode 0 is the invariant: normal exit, no signal. (No
        # elapsed assertion — worker-exit latency on a loaded host is
        # not flake-proof; the sentinel wait is event-driven anyway.)
        assert all(p.exitcode == 0 for p in procs)
        assert "clean drain" not in caplog.text
    finally:
        # Bounded on every failure path (idempotent after the clean
        # shutdown above): never leave an unshut pool behind.
        _shutdown_pool_nowait(pool)
        for p in procs:  # leak-guard for assertion failures above
            if p.is_alive():
                p.kill()


# Nightly tier: the escalation it forces pays the injected 0.5s grace
# plus the helper's fixed 5s terminate→kill window by design; adverse
# scheduling stacks on top of that genuine multi-second floor.
# Trade-off: the clean-path escalation wiring (grace → terminate →
# SIGKILL → warning, pipe released) surfaces regressions nightly, not
# per-PR. Accepted with the residual stated precisely: the escalation
# MECHANISM stays default-tier via the immune-worker test, and the
# clean path's happy direction via
# test_clean_shutdown_prompt_exit_no_escalation — only the
# clean-path-escalation combination itself is nightly-only.
@pytest.mark.slow
def test_clean_shutdown_escalates_on_exit_wedge(caplog) -> None:
    """A worker wedged AFTER its last result must not hang the clean
    shutdown: every result is already in hand, escalation fires
    within the grace bound with a warning naming the pid, and no
    orphan is left holding a parent-owned pipe."""
    import logging
    import select

    from core.inventory.builder import _shutdown_pool_clean, logger

    # Parent-owned pipe created BEFORE the pool: fork workers inherit
    # the write end (fork copies the fd table; non-inheritable flags
    # only matter across exec). EOF on the read end after teardown
    # proves no worker survived holding it — the exact leak class
    # that keeps a CI step's output pipe open.
    r, w = os.pipe()
    ctx = multiprocessing.get_context("fork")
    pool = ProcessPoolExecutor(
        max_workers=1, mp_context=ctx, initializer=_install_exit_wedge,
    )
    procs: list = []
    try:
        futs = [pool.submit(_square, i) for i in range(4)]
        # Capture BEFORE resolving: a failure below must still leave
        # the leak-guard something to kill — otherwise a failed
        # assertion strands the exit-wedged worker in its 600s
        # Finalize sleep and stalls the whole session.
        procs = list(pool._processes.values())
        assert procs
        results = [f.result(timeout=60) for f in futs]
        assert results == [i * i for i in range(4)]  # results integrity
        os.close(w)  # parent's copy; only workers hold it now
        w = -1  # closed marker for the failure-path finally below
        t0 = time.monotonic()
        with caplog.at_level(logging.WARNING, logger=logger.name):
            _shutdown_pool_clean(pool, grace_s=0.5)
        assert _wait_dead(procs, 10.0), "exit-wedged worker survived"
        assert time.monotonic() - t0 < 20.0
        assert "clean drain" in caplog.text
        assert str(procs[0].pid) in caplog.text
        assert procs[0].exitcode in (-signal.SIGTERM, -signal.SIGKILL)
        ready, _w_, _x = select.select([r], [], [], 10.0)
        assert ready, "pipe still held open — orphan holds the write end"
        assert os.read(r, 1) == b""  # true EOF, not data
    finally:
        os.close(r)
        if w >= 0:  # failure before the happy-path close above
            os.close(w)
        for p in procs:  # leak-guard for assertion failures above
            if p.is_alive():
                p.kill()


def test_init_inventory_worker_resets_sigterm() -> None:
    """The worker initializer must restore the default SIGTERM
    disposition — inherited parent handlers must never run inside an
    extractor worker."""
    prior = signal.getsignal(signal.SIGTERM)
    # The initializer also detaches fd 1/2 — running it IN-PROCESS
    # would point the test runner's own stdio at /dev/null and
    # swallow everything pytest prints afterwards (including failure
    # reports under -s). Save and restore the real descriptors.
    saved_out, saved_err = os.dup(1), os.dup(2)
    try:
        signal.signal(signal.SIGTERM, _blocking_handler)
        _init_inventory_worker(*_INIT_ARGS)
        assert signal.getsignal(signal.SIGTERM) is signal.SIG_DFL
    finally:
        os.dup2(saved_out, 1)
        os.dup2(saved_err, 2)
        os.close(saved_out)
        os.close(saved_err)
        signal.signal(signal.SIGTERM, prior)


def _write_to_inherited_stdio() -> None:
    os.write(1, b"WORKER-STDOUT-LEAK")
    os.write(2, b"WORKER-STDERR-LEAK")


def test_worker_stdio_detached_from_parent(capfd) -> None:
    """Initialized workers must not hold (or write to) the parent's
    stdout/stderr: a worker that never holds the pipe cannot keep a
    CI step's stream open no matter how it dies."""
    ctx = multiprocessing.get_context("fork")
    pool = ProcessPoolExecutor(
        max_workers=1, mp_context=ctx,
        initializer=_init_inventory_worker, initargs=_INIT_ARGS,
    )
    try:
        pool.submit(_write_to_inherited_stdio).result(timeout=60)
    finally:
        # The bounded teardown, not shutdown(wait=True): a fork
        # worker can wedge on a fork-frozen lock even AFTER its task
        # completed (pytest runs threads too), and an unbounded join
        # then hangs the whole test session.
        _shutdown_pool_nowait(pool)
    out, err = capfd.readouterr()
    assert "WORKER-STDOUT-LEAK" not in out
    assert "WORKER-STDERR-LEAK" not in err


def _fake_processing_error(fp: Path) -> dict:
    return {"path": str(fp), "_excluded": True,
            "_reason": "processing_error", "_pattern": "FakeError"}


def test_processing_error_is_revoiced_by_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog,
) -> None:
    """With worker stdio detached, the worker's own failure WARNING
    dies in /dev/null and the future succeeds — the parent must log
    the processing_error record or the failure is visible only in
    the artifact."""
    import logging

    from core.inventory import builder as builder_mod

    src = tmp_path / "proj"
    src.mkdir()
    for i in range(12):  # >10 files engages the parallel path
        (src / f"m_{i:02d}.py").write_text("def f():\n    return 1\n")
    # Fork context so the pool's children inherit the monkeypatch
    # (forkserver children are spawned from a pre-patch template).
    monkeypatch.setattr(
        builder_mod, "_pool_mp_context",
        lambda: multiprocessing.get_context("fork"),
    )
    monkeypatch.setattr(
        builder_mod, "_process_file_in_worker", _fake_processing_error,
    )
    with caplog.at_level(logging.WARNING, logger=builder_mod.logger.name):
        inv = builder_mod.build_inventory(
            str(src), output_dir=str(tmp_path / "out"),
        )
    assert any(
        "recorded as processing_error" in r.getMessage()
        for r in caplog.records
    )
    reasons = {e["reason"] for e in inv.get("excluded_files", [])}
    assert "processing_error" in reasons


def test_fork_worker_sheds_inherited_sigterm_handler() -> None:
    """End to end through a real fork pool: a parent-installed
    SIGTERM handler must not survive into the worker."""
    prior = signal.getsignal(signal.SIGTERM)
    pool = None
    try:
        signal.signal(signal.SIGTERM, _blocking_handler)
        ctx = multiprocessing.get_context("fork")
        pool = ProcessPoolExecutor(
            max_workers=1, mp_context=ctx,
            initializer=_init_inventory_worker, initargs=_INIT_ARGS,
        )
        assert pool.submit(_report_sigterm_is_default).result(
            timeout=60,
        ) is True
    finally:
        signal.signal(signal.SIGTERM, prior)
        if pool is not None:
            # The bounded teardown, not shutdown(wait=True): a fork
            # worker can wedge on a fork-frozen lock even AFTER its
            # task completed (pytest runs threads too), and an
            # unbounded join then hangs the whole test session.
            _shutdown_pool_nowait(pool)

"""Stress-test sweep — scans every sample in PROJECT_SAMPLES and
diffs against a committed baseline.

Catches the silent-regression class of bug. The OSV ``Cargo →
crates.io`` ecosystem-name fix landed in commit 4b0d40f5; before
the fix every Rust crate's CVE lookup quietly returned zero. Nothing
in the test suite or the validate/refit pipelines noticed —
``alacritty-0.13`` legitimately had 0 vuln findings, but so did
every Cargo project in the corpus, and the validation passed
because Cargo was already 0% signal density.

A baseline-driven stress sweep would have flagged this immediately:
"alacritty-0.13 vuln findings 6 → 0 (-100%)". The calibration
pipeline is metric-driven (precision / ρ); the stress sweep is
*invariant*-driven (these scans should produce ROUGHLY these
counts).

## Exit codes (when called from the GHA workflow or a script)

    0 — every project within tolerance
    1 — at least one warn (small drift; investigate)
    2 — at least one fail (large drift or new error)

## What's measured

Per project:
  * elapsed_seconds (wall-clock for run_sca)
  * deps_analysed (resolved + transitive)
  * vuln_findings (sca:vulnerable_dependency count)
  * eco_breakdown (per-finding-ecosystem distribution)

Elapsed is a single sample of a network-dominated process (identical
code has produced 30s and 183s cold scans of one project on one host
within minutes — per-registry throttling roulette). Callers should run
:func:`confirm_elapsed_regressions` between the sweep and the baseline
comparison: it re-measures projects whose only fail-level drift is
elapsed and keeps the better sample, so a genuine code regression
(which reproduces) still fails while one throttled run doesn't block
the sweep. Count drifts are never re-measured — they are
deterministic given upstream data.

Timeout-abandoned scans get the same variance treatment inside
:func:`run_stress_sweep` itself: the same registry roulette that
produces 5× elapsed noise can push the largest project past its
whole per-scan budget, so each timed-out scan is retried exactly
once at the end of the sweep, on a fresh full budget, against the
in-run caches the sweep just warmed — but only when its orphaned
worker has actually finished (see the retry pass for the safety
argument).

What's deliberately NOT measured:
  * Cache hit ratio (fluctuates with TTL eviction)
  * SCA total runtime when including supply-chain / hygiene checks
    that depend on registry HTTP responsiveness — those calls are
    cached but sometimes refresh
  * Memory usage — operator's local resources, not SCA-controlled

## Baseline format

    {
      "_source": {
        "name": "RAPTOR SCA stress-test baseline",
        "license": "MIT (RAPTOR-generated)",
        "captured_at": "2026-05-10T...",
        "captured_with_commit": "a9ad1b74",
        "sample_count": 41,
        ...
      },
      "projects": {
        "alacritty-0.13": {
          "ecosystem": "Cargo",
          "deps_analysed": 331,
          "vuln_findings": 6,
          "eco_breakdown": {"Cargo": 5, "Inline": 1},
          "elapsed_seconds_p50": 12.3
        },
        ...
      }
    }

When a baseline doesn't exist for a sample, that sample is reported
``new`` (informational, not a regression). When a baseline exists
but the corresponding sample no longer does, that's reported
``orphan``.
"""

from __future__ import annotations

import concurrent.futures
import logging
import os
import subprocess
import tempfile
import sys
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .project_samples import PROJECT_SAMPLES, ProjectSample

from core.json import load_json, save_json

# Read budget for the (small, committed) stress-baseline file.
# findings.json is deliberately NEVER re-read by this module: on
# large corpus projects the artifact legitimately runs to hundreds
# of MB, so any fixed read cap eventually turns a healthy scan into
# a silent "no findings" — the per-ecosystem breakdown comes from
# the in-process ``RunResult.eco_breakdown`` instead.
_MAX_BASELINE_BYTES = 64 * 1024 * 1024

logger = logging.getLogger(__name__)


# Tolerance bands. Operators can override per-call.
DEFAULT_VULN_WARN_PCT = 0.25       # ±25% → warn
DEFAULT_VULN_FAIL_PCT = 0.50       # ±50% → fail
DEFAULT_DEPS_WARN_PCT = 0.10       # ±10% → warn (parsers shift)
DEFAULT_DEPS_FAIL_PCT = 0.30       # ±30% → fail
DEFAULT_ELAPSED_WARN_X = 3.0       # 3× slower → warn
DEFAULT_ELAPSED_FAIL_X = 5.0       # 5× slower → fail
# Minimum baseline elapsed (seconds) for timing regression checks.
# Short scans are noise-dominated on CI runners — a 4s scan can
# vary 5-6× from network roundtrip and runner variance alone.
_ELAPSED_MIN_BASELINE_SECONDS = 10.0


@dataclass(frozen=True)
class StressResult:
    """Per-project scan diagnostics captured during the sweep."""

    project: str
    ecosystem: str
    elapsed_seconds: float
    deps_analysed: int
    vuln_findings: int
    eco_breakdown: dict[str, int]
    error: str | None = None  # populated when the scan itself failed


@dataclass(frozen=True)
class StressDiff:
    """Per-project comparison vs baseline."""

    project: str
    ecosystem: str
    severity: str           # "ok" / "warn" / "fail" / "new" / "orphan"
    issues: list[str] = field(default_factory=list)
    current: StressResult | None = None


def run_sweep_and_report(
    samples: Sequence[ProjectSample],
    baseline_path: Path,
    *,
    git_clone_timeout: int = 300,
    sca_timeout: int = 600,
    max_workers: int = 4,
    out: "Callable[[str], Any]" = print,
    driver_failure_sink: list[str] | None = None,
) -> tuple[int, list[StressResult]]:
    """Drive sweep → elapsed re-measure → baseline compare → render,
    and NEVER exit without a summary.

    A sweep run died mid-flight with neither a traceback nor a
    summary — the worst post-mortem shape. This driver makes every
    death mode name its killer:

    * per-scan raises already degrade the affected PROJECT with a
      named reason (endpoint distress — 429 storms, circuit-breaker
      fail-fast ``HttpError(circuit_break=True)``, retry exhaustion —
      lands here and shows as ``scan error: …`` in the summary);
    * a raise in any POST-SWEEP phase (re-measure, compare, render)
      prints the traceback AND a partial summary from whatever
      results exist, then reports rc=2;
    * SIGTERM (runner cancellation grace) prints the in-flight scans
      and the partial summary before the process dies;
    * hard kills (OOM SIGKILL) can print nothing — for those, the
      heartbeat and per-scan "scan starting" lines in the log are
      the post-mortem.

    Returns ``(rc, results)`` — rc per :func:`diffs_to_exit_code`,
    or 2 when a phase failed.

    ``driver_failure_sink``: caller-owned list (same pattern as
    ``results_sink``) that receives a one-line description of any
    driver-phase failure. rc=2 alone cannot tell "fail-level drift"
    from "the re-measure / compare / render phase crashed AFTER all
    scans completed" — the results list is then complete and
    error-free, exactly the shape a drift-only rc=2 has. Consumers
    that must never treat a crashed run as adjudicable drift (the
    baseline-refresh gate, :func:`decide_baseline_refresh`) key off
    this sink.
    """
    import signal
    import traceback

    results: list[StressResult] = []

    def _partial_summary(note: str) -> None:
        out(f"sweep interrupted — {note}")
        inflight = _in_flight()
        if inflight:
            out(f"in-flight scans: {', '.join(inflight)}")
        done = [r for r in results if r is not None]
        out(f"completed scans: {len(done)}/{len(samples)}")
        try:
            diffs = compare_to_baseline(done, baseline_path)
            out(render_diffs(diffs))
        except Exception:  # noqa: BLE001 — post-mortem best effort
            for r in done:
                out(f"  [done] {r.ecosystem}/{r.project} "
                    f"vulns={r.vuln_findings} err={r.error}")
        sys.stdout.flush()
        sys.stderr.flush()

    prior_term = signal.getsignal(signal.SIGTERM)
    handler_pid = os.getpid()

    def _on_term(signum: int, frame: object) -> None:
        if os.getpid() != handler_pid:
            # Fork-context children (inventory extractor workers, mp
            # helpers) inherit this handler. The post-mortem below
            # must never run in a child: its lock-taking
            # (``_in_flight``) can block forever on a lock some
            # sibling thread held at fork time — a terminate()d
            # worker then never dies — and its output would
            # interleave a bogus "sweep interrupted" summary into the
            # real log. Die like an unhandled SIGTERM instead.
            signal.signal(signal.SIGTERM, signal.SIG_DFL)
            signal.raise_signal(signal.SIGTERM)
            return
        _partial_summary("SIGTERM (cancellation / shutdown)")
        signal.signal(signal.SIGTERM, prior_term)
        signal.raise_signal(signal.SIGTERM)

    try:
        signal.signal(signal.SIGTERM, _on_term)
    except ValueError:
        prior_term = None      # not the main thread — no handler

    try:
        try:
            # ``results`` doubles as the live sink: completions land
            # in it AS THEY HAPPEN, so the SIGTERM / interrupt
            # post-mortem reports what actually finished instead of
            # claiming zero after forty completed scans.
            run_stress_sweep(
                samples=samples,
                git_clone_timeout=git_clone_timeout,
                sca_timeout=sca_timeout,
                max_workers=max_workers,
                results_sink=results,
            )
            results = confirm_elapsed_regressions(
                results, samples, baseline_path,
                git_clone_timeout=git_clone_timeout,
            )
            diffs = compare_to_baseline(results, baseline_path)
            out(render_diffs(diffs))
            sys.stdout.flush()
            return diffs_to_exit_code(diffs), results
        except KeyboardInterrupt:
            _partial_summary("KeyboardInterrupt")
            raise
        except BaseException as e:
            # Includes SystemExit: dying on it prints NOTHING (no
            # traceback, no summary). Name it, dump the partial
            # state, and report failure honestly.
            out("sweep driver caught "
                f"{type(e).__name__}: {str(e)[:300]}")
            out(traceback.format_exc())
            _partial_summary("driver-phase failure")
            if driver_failure_sink is not None:
                driver_failure_sink.append(
                    f"driver-phase failure: {type(e).__name__}: "
                    f"{str(e)[:200]}"
                )
            return 2, results
    finally:
        if prior_term is not None:
            try:
                signal.signal(signal.SIGTERM, prior_term)
            except ValueError:
                pass


def configure_sweep_logging(debug_log: Path) -> None:
    """Console + debug-file logging for a sweep driver process.

    Exactly ONE console handler (RAPTOR's canonical
    ``[LEVEL] message`` form, INFO) plus one DEBUG file handler.

    The driver must NOT call ``logging.basicConfig`` itself: the
    pipeline import happens lazily per sample (``_scan_one``), and
    RAPTOR's logging bootstrap attaches its own root console handler
    as an import side effect. A driver-installed bare handler then
    coexists with it — every record printed twice (bare + prefixed),
    which is exactly the duplication a stress-sweep run exhibited on
    every line of its log. Attaching RAPTOR's handler EAGERLY here
    (its sentinel guard makes the later import a no-op) keeps the
    console single-voiced and level-prefixed.
    """
    import logging

    from core.logging import get_logger

    get_logger()   # attaches the canonical [LEVEL] console handler
    root = logging.getLogger()
    # The file handler wants everything; the console handler stays
    # at INFO (set by the bootstrap).
    root.setLevel(logging.DEBUG)
    debug_log.parent.mkdir(parents=True, exist_ok=True)
    fh = logging.FileHandler(debug_log, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s: %(message)s",
    ))
    root.addHandler(fh)


def run_stress_sweep(
    *,
    samples: Sequence[ProjectSample] | None = None,
    out_root: Path | None = None,
    git_clone_timeout: float = 300,
    sca_timeout: float = 600,
    max_workers: int = 4,
    use_existing_clones: bool = False,
    results_sink: "list[StressResult] | None" = None,
) -> list[StressResult]:
    """Walk samples, scan each, return per-sample diagnostics.

    ``results_sink``: caller-owned list that receives each result AS
    IT COMPLETES (the returned list is the same object when given).
    Interrupt-time post-mortems need it — a signal handler cannot see
    this function's local state, and a partial summary that claims
    zero completions after forty finished scans is worse than none.

    Scans run in parallel (``max_workers`` threads). Each scan is
    bounded by its OWN budget of ``git_clone_timeout + sca_timeout``,
    measured from the moment a worker starts it (queue time excluded)
    — if it hasn't returned by then, a timeout result is recorded and
    the sweep continues. The scan thread itself cannot be killed and
    may linger until process exit, but won't block other scans or the
    final summary. After every other project has finished, each
    timeout-abandoned scan whose orphaned worker has completed is
    retried once on a fresh budget (see the retry pass below); a
    successful retry replaces the timeout result wholesale.

    ``out_root`` defaults to a STABLE per-machine path under
    ``~/.raptor/cache/sca/stress/clones/``. Stable so that the
    per-target inventory cache (``core/inventory/builder.default_cache_dir``)
    finds matching SHA-256 entries across sweep runs and short-
    circuits the inventory build. The clone subdir for each sample
    gets ``rm -rf``'d before re-cloning to avoid ``git clone:
    destination already exists`` — so the source files are fresh
    every run, but the resolved path stays the same, which is what
    the inventory cache keys on.

    Tests + one-shot callers that want a fresh tempdir pass an
    explicit ``out_root``. The tempdir+cleanup path triggers when
    the caller explicitly passes ``out_root=None`` AND sets the
    environment variable ``RAPTOR_SCA_STRESS_EPHEMERAL=1`` — the
    rare "I want zero state across runs" mode for diagnosing
    cache-pollution bugs.

    ``use_existing_clones`` is a no-op today (every scan re-clones).
    Reserved for a future caching mode that would skip the clone
    when the existing checkout matches ``sample.git_ref``.
    """
    if samples is None:
        samples = PROJECT_SAMPLES

    cleanup_dir: Path | None = None
    if out_root is None:
        if os.environ.get("RAPTOR_SCA_STRESS_EPHEMERAL"):
            # A dir orphaned by SIGTERM/OOM (which skips the
            # ``finally`` below) is reclaimed by the next run's sweep:
            # the raptor-sca-stress- prefix is listed in
            # core.run.tmp_reaper's static tuple. (A runtime
            # register_dir_prefix() call could not deliver that — it
            # dies with the process that made it.)
            cleanup_dir = Path(tempfile.mkdtemp(prefix="raptor-sca-stress-"))
            out_root = cleanup_dir
        else:
            from packages.sca import SCA_CACHE_ROOT
            out_root = SCA_CACHE_ROOT / "stress" / "clones"
    out_root.mkdir(parents=True, exist_ok=True)

    # Per-scan wall-clock budget: a scan must clone
    # (``git_clone_timeout``) and then scan (``sca_timeout``). The
    # budget is enforced against each scan's own start time — an
    # earlier revision applied it as a single global deadline from
    # sweep start, so once total wall time exceeded ONE scan's
    # budget every still-running or still-queued healthy project
    # was falsely reported as timed out.
    per_scan_budget = sca_timeout + git_clone_timeout
    results: list[StressResult] = (
        results_sink if results_sink is not None else []
    )

    # Heartbeat: one INFO line a minute naming the in-flight scans
    # (and this process's RSS). A sweep hard-killed mid-run (runner
    # OOM, forced cancellation) dies without a traceback or summary
    # — these lines are the post-mortem that names the killer
    # project(s). Daemon thread; dies with the sweep.
    _hb_stop = threading.Event()

    def _heartbeat() -> None:
        while not _hb_stop.wait(60):
            rss = "?"
            try:
                with open("/proc/self/status") as st:
                    for line in st:
                        if line.startswith("VmRSS"):
                            rss = f"{int(line.split()[1]) // 1024}MB"
                            break
            except OSError:
                pass
            logger.info(
                "sca.calibration.stress: heartbeat — in flight: %s "
                "(rss=%s)", ", ".join(_in_flight()) or "none", rss,
            )

    threading.Thread(target=_heartbeat, daemon=True).start()
    try:
        # Explicit executor lifecycle instead of a ``with`` block: on
        # KeyboardInterrupt the context manager's exit would call
        # shutdown(wait=True) and JOIN the in-flight workers — the
        # interrupt acknowledgement (partial summary, traceback)
        # would then wait out whatever scans were mid-run, minutes in
        # production. The interrupt path abandons them instead
        # (interpreter exit still joins pool threads; only the
        # acknowledgement is immediate).
        executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers,
        )
        interrupted = False
        # Futures whose scan overran its own budget. Their threads
        # cannot be killed — the future is dropped from ``pending``
        # (result already recorded) and the final shutdown skips
        # joining them.
        abandoned: set[concurrent.futures.Future] = set()
        # Timeout-abandoned scans eligible for the end-of-sweep
        # retry pass: (orphan future, sample, index of the timeout
        # result in ``results``), recorded at abandonment time.
        # Keying off the abandonment bookkeeping itself (rather than
        # error-string matching) scopes the retry to exactly the
        # timeout-abandonment shape.
        timeout_abandoned: list[
            tuple[concurrent.futures.Future, ProjectSample, int]
        ] = []
        try:
            future_to_sample = {
                executor.submit(
                    _scan_one, sample, out_root,
                    git_clone_timeout=git_clone_timeout,
                ): sample
                for sample in samples
            }
            sweep_labels = {
                f"{s.ecosystem}/{s.name}" for s in samples
            }
            pending: set[concurrent.futures.Future] = set(
                future_to_sample,
            )

            def _record(result: StressResult) -> None:
                results.append(result)
                logger.info(
                    "[%d/%d] %s/%s%s",
                    len(results), len(future_to_sample),
                    result.ecosystem, result.project,
                    " (error)" if result.error else "",
                )

            # Poll granularity for budget checks. ``wait`` returns
            # early on any completion, so the poll only bounds how
            # late an over-budget scan is detected.
            poll = min(1.0, max(0.05, per_scan_budget / 10.0))
            try:
                while pending:
                    done, _not_done = concurrent.futures.wait(
                        pending, timeout=poll,
                        return_when=concurrent.futures.FIRST_COMPLETED,
                    )
                    for future in done:
                        pending.discard(future)
                        sample = future_to_sample[future]
                        try:
                            result = future.result()
                        except BaseException as e:  # noqa: BLE001
                            # BaseException, not Exception: a library
                            # sys.exit() or comparable escape inside a
                            # scan thread must degrade THIS project with
                            # a named reason, never kill the sweep
                            # summary-less (an uncaught SystemExit exits
                            # with no traceback at all — the worst
                            # post-mortem). KeyboardInterrupt is the
                            # operator's and still propagates.
                            if isinstance(e, KeyboardInterrupt):
                                raise
                            result = StressResult(
                                project=sample.name,
                                ecosystem=sample.ecosystem,
                                elapsed_seconds=0.0,
                                deps_analysed=0, vuln_findings=0,
                                eco_breakdown={},
                                error=(
                                    f"unexpected {type(e).__name__}: "
                                    f"{str(e)[:200]}"
                                ),
                            )
                        _record(result)

                    # Per-scan budget check. Only scans that have
                    # actually STARTED (registered in the in-flight
                    # registry) can time out, and only against their
                    # own clock — queue time never counts.
                    now = time.monotonic()
                    for future in list(pending):
                        sample = future_to_sample[future]
                        label = f"{sample.ecosystem}/{sample.name}"
                        started = _scan_started_at(label)
                        if (started is None
                                or now - started <= per_scan_budget):
                            continue
                        pending.discard(future)
                        abandoned.add(future)
                        _record(StressResult(
                            project=sample.name,
                            ecosystem=sample.ecosystem,
                            elapsed_seconds=now - started,
                            deps_analysed=0, vuln_findings=0,
                            eco_breakdown={},
                            error=(
                                f"scan timed out: exceeded its "
                                f"{per_scan_budget}s budget (clone "
                                f"{git_clone_timeout}s + scan "
                                f"{sca_timeout}s); worker abandoned "
                                f"after {now - started:.0f}s"
                            ),
                        ))
                        timeout_abandoned.append(
                            (future, sample, len(results) - 1),
                        )

                    # Starvation escape: when EVERY worker is held by
                    # an over-budget scan, queued futures may never
                    # start and the loop would spin forever. Cancel
                    # them with an honest reason instead. Trade-off:
                    # an over-budget scan might still finish and free
                    # its worker, but each queued scan would then
                    # need a full budget of its own anyway — a
                    # bounded sweep beats the best-case save.
                    if pending and _over_budget_running(
                        sweep_labels, per_scan_budget,
                    ) >= max_workers:
                        for future in list(pending):
                            if not future.cancel():
                                # Already running — its own budget
                                # applies on later polls.
                                continue
                            pending.discard(future)
                            sample = future_to_sample[future]
                            _record(StressResult(
                                project=sample.name,
                                ecosystem=sample.ecosystem,
                                elapsed_seconds=0.0,
                                deps_analysed=0, vuln_findings=0,
                                eco_breakdown={},
                                error=(
                                    "never started: all "
                                    f"{max_workers} worker(s) held "
                                    "by over-budget scans"
                                ),
                            ))

                # ── End-of-sweep retry for timeout-abandoned scans ──
                # A scan's wall clock is one sample of a network-
                # dominated process (see confirm_elapsed_regressions):
                # the same registry roulette behind 5× elapsed noise
                # can push the largest project past its whole budget,
                # and that single sample then errors the project and
                # blocks any baseline refresh. Retry each timeout-
                # abandoned scan exactly ONCE, sequentially, on a
                # fresh full budget — cheap in the common case
                # because the sweep just warmed the in-run registry
                # caches (cold/warm pairs on one project have
                # measured ~18×). Headroom-via-retry deliberately
                # beats headroom-via-bigger-budget: a larger
                # ``sca_timeout`` would also stretch every genuinely
                # hung scan by the same amount.
                #
                # Scope is timeout-ABANDONMENT only. Clone failures
                # and clone timeouts return normally from the worker
                # (``subprocess`` timeout) — no orphan, and no warm-
                # cache advantage either: the clone talks to the git
                # host, not the registry caches the sweep warmed.
                # "Never started" cancellations and driver crashes
                # are not variance evidence. None of those retry.
                #
                # Concurrency safety: the orphaned worker cannot be
                # killed, so a retry must never overlap it on the
                # same clone dir / shared caches. ``orphan.done()``
                # is a sufficient gate: the executor sets a future's
                # result strictly AFTER ``_scan_one`` returns — i.e.
                # after every filesystem write and the in-flight-
                # registry pop in its ``finally`` — so a done orphan
                # makes no further writes. Nor can a late orphan
                # clobber the retry's RESULT: abandonment removed the
                # orphan from ``pending``, and only futures still in
                # ``pending`` are ever read into ``results``. When
                # the orphan is still running at its retry slot, the
                # retry is skipped and the timeout error stands —
                # never two concurrent scans of one project.
                for orphan, sample, idx in timeout_abandoned:
                    label = f"{sample.ecosystem}/{sample.name}"
                    if not orphan.done():
                        logger.info(
                            "sca.calibration.stress: timeout retry "
                            "for %s — orphan still running, retry "
                            "skipped (keeping the timeout error)",
                            label,
                        )
                        continue
                    logger.info(
                        "sca.calibration.stress: timeout retry for "
                        "%s — orphan finished; retrying once on a "
                        "fresh %.0fs budget (warm in-run cache)",
                        label, per_scan_budget,
                    )
                    # Dedicated single-thread pool, not the sweep
                    # executor: the sweep pool's threads can ALL be
                    # held by other still-running orphans, and a
                    # queued retry would have its fresh budget eaten
                    # by queue time. A fresh thread starts the scan
                    # immediately, so measuring the budget from
                    # submit is measuring it from work start.
                    retry_pool = concurrent.futures.ThreadPoolExecutor(
                        max_workers=1,
                        thread_name_prefix="sca-stress-timeout-retry",
                    )
                    try:
                        retry = retry_pool.submit(
                            _scan_one, sample, out_root,
                            git_clone_timeout=git_clone_timeout,
                        )
                        try:
                            second = retry.result(
                                timeout=per_scan_budget,
                            )
                        except KeyboardInterrupt:
                            raise
                        except concurrent.futures.TimeoutError:
                            # Ambiguous re-raise: ``result(timeout=)``
                            # raises TimeoutError when the WAIT
                            # expired, when the scan fn itself raised
                            # one, and when the fn finished a moment
                            # AFTER the wait expired. All three keep
                            # the original timeout error (the budget
                            # is the verdict); the split below is for
                            # log accuracy only.
                            if not retry.done():
                                # The retry worker is now its own
                                # orphan — never joined, like any
                                # other abandoned scan; there is no
                                # second retry.
                                logger.warning(
                                    "sca.calibration.stress: timeout "
                                    "retry for %s — retry also timed "
                                    "out; keeping the original "
                                    "timeout error", label,
                                )
                            elif (exc := retry.exception()) is not None:
                                logger.warning(
                                    "sca.calibration.stress: timeout "
                                    "retry for %s — retry raised "
                                    "%s; keeping the original "
                                    "timeout error", label,
                                    type(exc).__name__,
                                )
                            else:
                                logger.warning(
                                    "sca.calibration.stress: timeout "
                                    "retry for %s — retry finished "
                                    "just past its budget; keeping "
                                    "the original timeout error",
                                    label,
                                )
                            continue
                        except BaseException as e:  # noqa: BLE001
                            # Same degrade-not-die posture as the
                            # sweep loop: a raising retry keeps the
                            # original timeout error.
                            logger.warning(
                                "sca.calibration.stress: timeout "
                                "retry for %s — retry raised %s: %s; "
                                "keeping the original timeout error",
                                label, type(e).__name__, str(e)[:200],
                            )
                            continue
                    finally:
                        # wait=False: a timed-out retry must not
                        # block the summary on its own thread.
                        retry_pool.shutdown(wait=False)
                    if second.error is not None:
                        logger.warning(
                            "sca.calibration.stress: timeout retry "
                            "for %s — retry errored (%s); keeping "
                            "the original timeout error",
                            label, second.error,
                        )
                        continue
                    # Wholesale replacement — counts, breakdown AND
                    # elapsed all from the successful attempt,
                    # matching the re-measure convention of using
                    # the re-measured timing. (Unlike an elapsed
                    # re-measure there is no count verdict to
                    # preserve: the timed-out attempt produced no
                    # counts at all.) In-place so ``results_sink``
                    # consumers see the replacement too.
                    results[idx] = second
                    logger.info(
                        "sca.calibration.stress: timeout retry for "
                        "%s — succeeded in %.1fs (warm cache); "
                        "timeout result replaced",
                        label, second.elapsed_seconds,
                    )
            except KeyboardInterrupt:
                # Ctrl-C / SIGINT: without this, a plain shutdown
                # drains the ENTIRE queued backlog (queued items
                # still execute) — a production interrupt could
                # grind on for the rest of the sweep before any
                # acknowledgement. Cancel what never started,
                # abandon what is running, re-raise.
                interrupted = True
                executor.shutdown(wait=False, cancel_futures=True)
                raise
        finally:
            if not interrupted:
                # Abandoned (over-budget) scans cannot be joined
                # without blocking the summary on exactly the scans
                # the budget bounds — skip the join when any exist
                # (interpreter exit still joins pool threads).
                executor.shutdown(wait=not abandoned)
    finally:
        _hb_stop.set()
        if cleanup_dir is not None:
            try:
                _rmtree(cleanup_dir)
            except OSError:
                pass
    return results


# In-flight scan registry — read by the heartbeat and the
# signal-time post-mortem so a hard-killed sweep (runner OOM,
# cancellation) still names the scans it died holding. Keyed
# "eco/name" → monotonic start time.
_ACTIVE_SCANS: dict[str, float] = {}
_ACTIVE_SCANS_LOCK = threading.Lock()


def _in_flight() -> list[str]:
    """Names of currently-running scans, longest-running first."""
    with _ACTIVE_SCANS_LOCK:
        items = sorted(_ACTIVE_SCANS.items(), key=lambda kv: kv[1])
    return [k for k, _ in items]


def _scan_started_at(label: str) -> float | None:
    """Monotonic start time of a currently-running scan, or None
    when it hasn't started (still queued) or already finished."""
    with _ACTIVE_SCANS_LOCK:
        return _ACTIVE_SCANS.get(label)


def _over_budget_running(labels: set[str], budget: float) -> int:
    """Count of THIS sweep's currently-running scans older than
    ``budget``. Restricted to the sweep's own labels so a
    concurrent sweep in the same process can't inflate the count."""
    now = time.monotonic()
    with _ACTIVE_SCANS_LOCK:
        return sum(
            1 for label, t0 in _ACTIVE_SCANS.items()
            if label in labels and now - t0 > budget
        )


def _scan_one(
    sample: ProjectSample,
    out_root: Path,
    *,
    git_clone_timeout: float,
) -> StressResult:
    label = f"{sample.ecosystem}/{sample.name}"
    logger.info("sca.calibration.stress: scan starting: %s", label)
    with _ACTIVE_SCANS_LOCK:
        _ACTIVE_SCANS[label] = time.monotonic()
    try:
        return _scan_one_inner(
            sample, out_root, git_clone_timeout=git_clone_timeout,
        )
    finally:
        with _ACTIVE_SCANS_LOCK:
            _ACTIVE_SCANS.pop(label, None)


def _scan_one_inner(
    sample: ProjectSample,
    out_root: Path,
    *,
    git_clone_timeout: float,
) -> StressResult:
    proj_out = out_root / f"{sample.ecosystem}-{sample.name}"
    proj_out.mkdir(parents=True, exist_ok=True)
    clone_root = proj_out / "src"
    sca_out = proj_out / "out"

    # Clean residue from prior runs. The ``out_root`` stays stable
    # across sweeps (so the inventory cache's resolved-abs-path key
    # finds its checklist), but the clone itself must be fresh —
    # ``git clone`` refuses to write into an existing directory.
    # The previous run's ``sca_out`` is also cleaned so a stale
    # findings.json from a different ref doesn't get mixed in.
    _rmtree(clone_root)
    _rmtree(sca_out)

    try:
        from core.config import RaptorConfig
        from core.git.clone import safe_git_command
        from core.sandbox.preexec import set_pdeathsig
        subprocess.run(
            safe_git_command(
                "clone", "--depth", "1",
                "--branch", sample.git_ref,
                sample.repo_url, str(clone_root),
            ),
            check=True, capture_output=True, text=True,
            timeout=git_clone_timeout,
            # preserve_proxy: remote clone — git honours proxy env.
            env=RaptorConfig.get_safe_env(preserve_proxy=True),
            preexec_fn=set_pdeathsig(),
        )
    except (subprocess.TimeoutExpired,
            subprocess.CalledProcessError) as e:
        err = (
            e.stderr if isinstance(e, subprocess.CalledProcessError)
            else f"clone timed out after {git_clone_timeout}s"
        )
        return StressResult(
            project=sample.name, ecosystem=sample.ecosystem,
            elapsed_seconds=0.0, deps_analysed=0,
            vuln_findings=0, eco_breakdown={},
            error=f"git clone failed: {str(err)[:200]}",
        )

    t0 = time.monotonic()
    try:
        from packages.sca.pipeline import RunOptions, run_sca
        run_result = run_sca(
            target=clone_root, output_dir=sca_out,
            options=RunOptions(
                enable_llm_review=False, enable_triage=False,
                # Stress sweeps run dozens of scans back-to-back; the
                # per-stage progress output noise dwarfs the actual
                # diagnostics. Auto-disable would already kick in for
                # non-TTY but explicit is safer.
                enable_progress=False,
            ),
        )
    except Exception as e:                                  # noqa: BLE001
        return StressResult(
            project=sample.name, ecosystem=sample.ecosystem,
            elapsed_seconds=time.monotonic() - t0,
            deps_analysed=0, vuln_findings=0, eco_breakdown={},
            error=f"run_sca failed: {str(e)[:200]}",
        )
    elapsed = time.monotonic() - t0

    return StressResult(
        project=sample.name, ecosystem=sample.ecosystem,
        elapsed_seconds=elapsed,
        deps_analysed=run_result.deps_analysed,
        vuln_findings=run_result.vuln_findings,
        # In-process breakdown from the same finding list the
        # ``vuln_findings`` count comes from. Re-reading the
        # written findings.json here would put a size cap between
        # the scan and its own numbers — an over-cap artifact then
        # reads back as an empty breakdown, indistinguishable from
        # a real zero-finding scan, and a baseline captured from it
        # would bake that ``{}`` in.
        eco_breakdown=dict(run_result.eco_breakdown),
    )


def confirm_elapsed_regressions(
    results: Sequence[StressResult],
    samples: Sequence[ProjectSample],
    baseline_path: Path,
    *,
    out_root: Path | None = None,
    git_clone_timeout: int = 300,
    max_remeasures: int = 3,
    vuln_warn_pct: float = DEFAULT_VULN_WARN_PCT,
    vuln_fail_pct: float = DEFAULT_VULN_FAIL_PCT,
    deps_warn_pct: float = DEFAULT_DEPS_WARN_PCT,
    deps_fail_pct: float = DEFAULT_DEPS_FAIL_PCT,
    elapsed_warn_x: float = DEFAULT_ELAPSED_WARN_X,
    elapsed_fail_x: float = DEFAULT_ELAPSED_FAIL_X,
) -> list[StressResult]:
    """Re-measure projects whose ONLY elapsed drift pushed them to
    warn or fail level, and fold the better sample in.

    A scan's wall clock is one sample of a network-dominated
    process: identical code produced 30s and 183s cold scans of the
    same project on the same host within minutes (per-registry
    throttling roulette). Comparing one noisy sample against the
    baseline's single sample turns that roulette into blocking sweep
    failures and, at the warn multiplier, into recurring
    single-sample noise in the report (a 52.7s throttled scan that
    re-measured to 3.6s proved the class). Counts don't have this
    problem — they are deterministic given upstream data — so only
    elapsed-driven drift is re-measured, at BOTH severities.

    For each such project (bounded by ``max_remeasures``): scan it
    once more and keep the re-scan result with ``elapsed_seconds =
    min(first, second)``. Registry stalls only ever ADD time, so the
    machine's best observed time is the lowest-noise estimate of what
    the code costs; a genuine code regression slows every sample, so
    it survives the min and still fails. Thresholds are NOT relaxed
    and no project is special-cased. A re-scan that itself errors
    leaves the original result in place (a flaky re-measure must not
    upgrade a timing fail into a scan-error fail).

    Returns a new results list; the input is not mutated.
    """
    baseline = _load_baseline(baseline_path)
    baseline_projects: dict[str, dict[str, Any]] = (
        baseline.get("projects") or {}
    )
    by_name = {s.name: s for s in samples}

    def _severity(result: StressResult, *, ignore_elapsed: bool) -> str:
        entry = baseline_projects.get(result.project)
        if entry is None or result.error:
            return "fail" if result.error else "new"
        _issues, severity = _diff_one(
            entry, result,
            vuln_warn_pct=vuln_warn_pct, vuln_fail_pct=vuln_fail_pct,
            deps_warn_pct=deps_warn_pct, deps_fail_pct=deps_fail_pct,
            elapsed_warn_x=(
                float("inf") if ignore_elapsed else elapsed_warn_x
            ),
            elapsed_fail_x=(
                float("inf") if ignore_elapsed else elapsed_fail_x
            ),
        )
        return severity

    if out_root is None:
        from packages.sca import SCA_CACHE_ROOT
        out_root = SCA_CACHE_ROOT / "stress" / "clones"

    _RANK = {"ok": 0, "new": 0, "warn": 1, "fail": 2}

    def _elapsed_raised_to(result: StressResult) -> str | None:
        """The severity the elapsed dimension ALONE raised this
        project to (ok→warn, ok→fail, warn→fail), or None when
        elapsed isn't the cause. Count drift keeps whatever severity
        it earns either way."""
        if result.error is not None:
            return None
        with_elapsed = _severity(result, ignore_elapsed=False)
        without_elapsed = _severity(result, ignore_elapsed=True)
        if _RANK.get(with_elapsed, 0) > _RANK.get(without_elapsed, 0):
            return with_elapsed
        return None

    def _elapsed_fired(result: StressResult) -> bool:
        """True when the elapsed dimension produced an issue line at
        all — including rows whose SEVERITY already comes from count
        drift. A count-warn row with a 3.6x elapsed line skipped
        re-measurement under raised-only eligibility, so throttle
        noise kept reaching the report glued to genuine count drift."""
        if result.error is not None:
            return False
        entry = baseline_projects.get(result.project)
        if entry is None:
            return False
        be = float(entry.get("elapsed_seconds_p50", 0.0) or 0.0)
        if be < _ELAPSED_MIN_BASELINE_SECONDS:
            return False
        return result.elapsed_seconds / be >= elapsed_warn_x

    # Budget priority: severity-raising FAILS, then severity-raising
    # warns, then elapsed lines riding count-drifted rows. The budget
    # is shared and the sweep is input-ordered, so lower tiers must
    # never starve a genuine elapsed-only FAIL — blocking the sweep
    # with exactly the single-sample noise this mechanism exists to
    # absorb.
    raised_by: dict[str, str] = {}
    for result in results:
        raised = _elapsed_raised_to(result)
        if raised is not None:
            raised_by[result.project] = raised
    budget_order = (
        [r.project for r in results if raised_by.get(r.project) == "fail"]
        + [r.project for r in results if raised_by.get(r.project) == "warn"]
        + [r.project for r in results
           if r.project not in raised_by and _elapsed_fired(r)]
    )
    approved = set(budget_order[:max_remeasures])

    out: list[StressResult] = []
    remeasured = 0
    for result in results:
        elapsed_raised = result.project in approved
        if not elapsed_raised or remeasured >= max_remeasures:
            out.append(result)
            continue
        sample = by_name.get(result.project)
        if sample is None:
            out.append(result)
            continue
        remeasured += 1
        logger.info(
            "sca.calibration.stress: elapsed %s for %s "
            "(%.1fs) — re-measuring to separate code regression "
            "from registry-throughput variance",
            raised_by.get(result.project, "noise on a count-drifted row"),
            result.project, result.elapsed_seconds,
        )
        second = _scan_one(
            sample, out_root, git_clone_timeout=git_clone_timeout,
        )
        if second.error is not None:
            logger.warning(
                "sca.calibration.stress: re-measure of %s errored "
                "(%s); keeping the original sample",
                result.project, second.error,
            )
            out.append(result)
            continue
        best = min(result.elapsed_seconds, second.elapsed_seconds)
        logger.info(
            "sca.calibration.stress: %s re-measured — samples "
            "%.1fs / %.1fs, using %.1fs",
            result.project, result.elapsed_seconds,
            second.elapsed_seconds, best,
        )
        # Elapsed-ONLY fold: counts always stay from the FIRST scan.
        # Taking the re-scan's counts would let a transient
        # count difference between the two scans launder (or invent)
        # count drift under the guise of a timing re-measure — count
        # verdicts and timing verdicts must stay independent.
        out.append(StressResult(
            project=result.project,
            ecosystem=result.ecosystem,
            elapsed_seconds=best,
            deps_analysed=result.deps_analysed,
            vuln_findings=result.vuln_findings,
            eco_breakdown=result.eco_breakdown,
        ))
    return out


def compare_to_baseline(
    results: Sequence[StressResult],
    baseline_path: Path,
    *,
    vuln_warn_pct: float = DEFAULT_VULN_WARN_PCT,
    vuln_fail_pct: float = DEFAULT_VULN_FAIL_PCT,
    deps_warn_pct: float = DEFAULT_DEPS_WARN_PCT,
    deps_fail_pct: float = DEFAULT_DEPS_FAIL_PCT,
    elapsed_warn_x: float = DEFAULT_ELAPSED_WARN_X,
    elapsed_fail_x: float = DEFAULT_ELAPSED_FAIL_X,
) -> list[StressDiff]:
    """Compare current sweep results against the baseline file.

    Missing baseline ⇒ every project reported ``new`` (informational).
    Missing project in current ⇒ ``orphan`` in the diff list.
    """
    baseline = _load_baseline(baseline_path)
    baseline_projects: dict[str, dict[str, Any]] = (
        baseline.get("projects") or {}
    )
    diffs: list[StressDiff] = []
    seen_in_current: set = set()

    for result in results:
        seen_in_current.add(result.project)
        # Errored scans are always fail.
        if result.error:
            diffs.append(StressDiff(
                project=result.project,
                ecosystem=result.ecosystem,
                severity="fail",
                issues=[f"scan error: {result.error}"],
                current=result,
            ))
            continue
        baseline_entry = baseline_projects.get(result.project)
        if baseline_entry is None:
            diffs.append(StressDiff(
                project=result.project,
                ecosystem=result.ecosystem,
                severity="new",
                issues=[
                    (f"new project (vuln_findings={result.vuln_findings}, "
                    f"deps={result.deps_analysed}); update baseline "
                    f"to commit")
                ],
                current=result,
            ))
            continue
        issues, severity = _diff_one(
            baseline_entry, result,
            vuln_warn_pct=vuln_warn_pct, vuln_fail_pct=vuln_fail_pct,
            deps_warn_pct=deps_warn_pct, deps_fail_pct=deps_fail_pct,
            elapsed_warn_x=elapsed_warn_x,
            elapsed_fail_x=elapsed_fail_x,
        )
        diffs.append(StressDiff(
            project=result.project,
            ecosystem=result.ecosystem,
            severity=severity,
            issues=issues,
            current=result,
        ))

    # Orphans — projects in baseline but not in current sweep.
    for proj, entry in baseline_projects.items():
        if proj in seen_in_current:
            continue
        diffs.append(StressDiff(
            project=proj,
            ecosystem=entry.get("ecosystem", "?"),
            severity="orphan",
            issues=[
                ("in baseline but not in current sweep — sample "
                "was removed?")
            ],
            current=None,
        ))
    return diffs


def _diff_one(
    baseline: dict[str, Any],
    current: StressResult,
    *,
    vuln_warn_pct: float, vuln_fail_pct: float,
    deps_warn_pct: float, deps_fail_pct: float,
    elapsed_warn_x: float, elapsed_fail_x: float,
) -> tuple[list[str], str]:
    issues: list[str] = []
    severity = "ok"

    # Vuln-finding count drift.
    bv = int(baseline.get("vuln_findings", 0) or 0)
    if bv > 0:
        signed_pct = (current.vuln_findings - bv) / bv
        abs_pct = abs(signed_pct)
        if abs_pct >= vuln_fail_pct:
            severity = "fail"
            issues.append(
                f"vuln_findings {bv} → {current.vuln_findings} "
                f"({signed_pct*100:+.0f}%, ≥ {vuln_fail_pct*100:.0f}% fail)"
            )
        elif abs_pct >= vuln_warn_pct:
            if severity == "ok":
                severity = "warn"
            issues.append(
                f"vuln_findings {bv} → {current.vuln_findings} "
                f"({signed_pct*100:+.0f}%, ≥ {vuln_warn_pct*100:.0f}% warn)"
            )
    # Baseline was 0 vuln_findings; flag any non-zero current as
    # warn so an OSV-Cargo-shaped fix that suddenly STARTS finding
    # vulns is loud.
    elif current.vuln_findings > 0:
        if severity == "ok":
            severity = "warn"
        issues.append(
            f"vuln_findings 0 → {current.vuln_findings} "
            f"(baseline was 0; intentional? update baseline)"
        )

    # Deps-analysed drift (parser regressions).
    bd = int(baseline.get("deps_analysed", 0) or 0)
    if bd > 0:
        signed_pct = (current.deps_analysed - bd) / bd
        abs_pct = abs(signed_pct)
        if abs_pct >= deps_fail_pct:
            severity = "fail"
            issues.append(
                f"deps_analysed {bd} → {current.deps_analysed} "
                f"({signed_pct*100:+.0f}%, ≥ {deps_fail_pct*100:.0f}% fail)"
            )
        elif abs_pct >= deps_warn_pct:
            if severity == "ok":
                severity = "warn"
            issues.append(
                f"deps_analysed {bd} → {current.deps_analysed} "
                f"({signed_pct*100:+.0f}%, ≥ {deps_warn_pct*100:.0f}% warn)"
            )

    # Eco-breakdown drift — flag NEW eco categories appearing
    # (interesting but not failure-worthy unless huge).
    base_ecos = set(baseline.get("eco_breakdown") or {})
    new_ecos = set(current.eco_breakdown) - base_ecos
    missing_ecos = base_ecos - set(current.eco_breakdown)
    if new_ecos:
        if severity == "ok":
            severity = "warn"
        issues.append(f"new eco categories: {sorted(new_ecos)}")
    if missing_ecos:
        if severity == "ok":
            severity = "warn"
        issues.append(f"eco categories disappeared: {sorted(missing_ecos)}")

    be = float(baseline.get("elapsed_seconds_p50", 0.0) or 0.0)
    if be >= _ELAPSED_MIN_BASELINE_SECONDS:
        ratio = current.elapsed_seconds / be
        if ratio >= elapsed_fail_x:
            severity = "fail"
            issues.append(
                f"elapsed {be:.1f}s → {current.elapsed_seconds:.1f}s "
                f"({ratio:.1f}× ≥ {elapsed_fail_x:.0f}× fail)"
            )
        elif ratio >= elapsed_warn_x:
            if severity == "ok":
                severity = "warn"
            issues.append(
                f"elapsed {be:.1f}s → {current.elapsed_seconds:.1f}s "
                f"({ratio:.1f}× ≥ {elapsed_warn_x:.0f}× warn)"
            )

    return issues, severity


def write_baseline(
    results: Sequence[StressResult],
    baseline_path: Path,
    *,
    captured_with_commit: str | None = None,
) -> None:
    """Capture current sweep results as the new baseline file."""
    projects: dict[str, dict[str, Any]] = {}
    for r in results:
        if r.error:
            # Don't bake error states into the baseline — that would
            # silently green-light a regression-by-error.
            continue
        projects[r.project] = {
            "ecosystem": r.ecosystem,
            "deps_analysed": r.deps_analysed,
            "vuln_findings": r.vuln_findings,
            "eco_breakdown": dict(sorted(r.eco_breakdown.items())),
            "elapsed_seconds_p50": round(r.elapsed_seconds, 1),
        }
    output = {
        # ``_source`` (rather than the originally-planned ``_meta``)
        # to satisfy the calibration corpus's license-check
        # convention — every JSON under ``data/calibration/`` carries
        # a ``_source`` block declaring its license + provenance.
        # Stress-baseline data is RAPTOR-generated (no third-party
        # content embedded), MIT-licensed, regenerated locally.
        "_source": {
            "name": "RAPTOR SCA stress-test baseline",
            "url": "internal — packages.sca.calibration.stress",
            "license": (
                "MIT (RAPTOR-generated). Captured per-sample "
                "diagnostics (deps_analysed, vuln_findings, "
                "eco_breakdown, elapsed_seconds_p50) for "
                "regression detection — no third-party content."
            ),
            "captured_at": datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ",
            ),
            "captured_with_commit": captured_with_commit or "unknown",
            "sample_count": len(projects),
            "provenance": (
                "Output of ``run_stress_sweep`` against "
                "``project_samples`` in the calibration corpus. "
                "Re-generated by an operator calling "
                "``write_baseline()`` after intentional changes "
                "to the samples list, parser logic, or scoring "
                "formula."
            ),
        },
        "projects": dict(sorted(projects.items())),
    }
    save_json(baseline_path, output, sort_keys=True)


def _load_baseline(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        data = load_json(path, strict=True, max_bytes=_MAX_BASELINE_BYTES)
        if data is not None:
            return data
        # is_file()/load race — treat like a read failure below.
        raise FileNotFoundError(path)
    except (OSError, ValueError) as e:
        logger.warning(
            "sca.calibration.stress: baseline read failed (%s); "
            "treating as empty", e,
        )
        return {}


def _rmtree(path: Path) -> None:
    """Recursive rm — avoids importing shutil at module top, since
    a stress sweep that doesn't pass through this code path
    (e.g., caller-supplied out_root) shouldn't pay the import."""
    import shutil
    shutil.rmtree(path, ignore_errors=True)


# Human-readable labels for the severity enum. Only the rendered
# text block uses them — data structures and JSON keep the
# lowercase enum values (``StressDiff.severity``, exit-code logic).
_SEVERITY_LABELS = {
    "ok": "Ok", "warn": "Warn", "fail": "Fail",
    "new": "New", "orphan": "Orphan",
}


def render_diffs(diffs: Sequence[StressDiff]) -> str:
    """Render diff results as a human-readable text block."""
    lines: list[str] = []
    counts = {"ok": 0, "warn": 0, "fail": 0, "new": 0, "orphan": 0}
    for d in diffs:
        counts[d.severity] = counts.get(d.severity, 0) + 1

    lines.append(
        f"summary: {len(diffs)} project(s); "
        f"Ok={counts['ok']} Warn={counts['warn']} "
        f"Fail={counts['fail']} New={counts['new']} "
        f"Orphan={counts['orphan']}"
    )

    # Order diffs: fail > warn > new > orphan > ok
    severity_rank = {"fail": 0, "warn": 1, "new": 2, "orphan": 3, "ok": 4}
    for d in sorted(diffs, key=lambda x: (
        severity_rank.get(x.severity, 9), x.project,
    )):
        label = _SEVERITY_LABELS.get(d.severity, d.severity)
        prefix = f"  [{label:^6s}] {d.ecosystem}/{d.project}"
        if not d.issues:
            lines.append(prefix)
            continue
        lines.append(prefix + ":")
        lines.extend(f"             {issue}" for issue in d.issues)
    return "\n".join(lines)


def diffs_to_exit_code(diffs: Sequence[StressDiff]) -> int:
    """0 ok / 1 warn / 2 fail. ``new`` and ``orphan`` are
    informational and don't affect the exit code."""
    if any(d.severity == "fail" for d in diffs):
        return 2
    if any(d.severity == "warn" for d in diffs):
        return 1
    return 0


@dataclass(frozen=True)
class BaselineRefreshDecision:
    """Verdict on whether a sweep's results may become the new
    baseline, plus the human-readable reason either way."""

    allowed: bool
    reason: str


def decide_baseline_refresh(
    rc: int,
    results: Sequence[StressResult],
    *,
    operator_refresh: bool = False,
    expected_count: int | None = None,
    driver_failures: Sequence[str] = (),
) -> BaselineRefreshDecision:
    """Gate every baseline capture a sweep driver performs.

    ``rc`` is the sweep exit code (:func:`diffs_to_exit_code`, or 2
    for a driver-phase failure). Without ``operator_refresh`` the
    verdict matches the long-standing behaviour: warn-only drift
    (rc=1) refreshes, fail (rc=2) never does — the operator must
    investigate first.

    ``operator_refresh`` is the investigated-and-adjudicated signal
    (a manual workflow dispatch with the ``refresh-baseline`` input
    set). It extends the refresh to fail-level drift — but ONLY when
    every fail IS drift. Any errored scan (clone failure, timeout,
    driver exception surfaced as ``StressResult.error``) refuses the
    whole refresh: :func:`write_baseline` silently skips errored
    projects, so the captured file would bless a partial run as the
    expected state. An incomplete result set (fewer results than
    ``expected_count``) refuses for the same reason, and so does any
    entry in ``driver_failures`` (:func:`run_sweep_and_report`'s
    ``driver_failure_sink``): a post-sweep phase crash leaves a
    complete, error-free results list whose rc=2 was earned by the
    crash, not by adjudicable drift — count checks alone cannot see
    it.
    """
    if rc == 0:
        return BaselineRefreshDecision(
            allowed=False,
            reason="no drift — baseline already current",
        )
    if rc == 1:
        return BaselineRefreshDecision(
            allowed=True, reason="warn-only drift",
        )
    if not operator_refresh:
        return BaselineRefreshDecision(
            allowed=False,
            reason=(
                "fail-level drift — operator must investigate "
                "(dispatch with refresh-baseline=true once the "
                "drift is adjudicated as legitimate)"
            ),
        )
    if driver_failures:
        return BaselineRefreshDecision(
            allowed=False,
            reason=(
                f"refusing operator refresh: the sweep driver itself "
                f"failed ({'; '.join(driver_failures)[:300]}) — this "
                "rc=2 was earned by the crash, not by adjudicable "
                "drift; a baseline is never captured from a broken run"
            ),
        )
    errored = [r for r in results if r.error is not None]
    if errored:
        names = ", ".join(
            f"{r.ecosystem}/{r.project}" for r in errored
        )
        return BaselineRefreshDecision(
            allowed=False,
            reason=(
                f"refusing operator refresh: {len(errored)} scan(s) "
                f"errored ({names}) — a baseline is never captured "
                "from a broken run; re-dispatch once the errors are "
                "resolved"
            ),
        )
    if expected_count is not None and len(results) < expected_count:
        return BaselineRefreshDecision(
            allowed=False,
            reason=(
                f"refusing operator refresh: only {len(results)} of "
                f"{expected_count} scans completed — a partial sweep "
                "must not become the baseline"
            ),
        )
    return BaselineRefreshDecision(
        allowed=True,
        reason="operator-adjudicated fail-level drift",
    )


__all__ = [
    "DEFAULT_DEPS_FAIL_PCT", "DEFAULT_DEPS_WARN_PCT",
    "DEFAULT_ELAPSED_FAIL_X", "DEFAULT_ELAPSED_WARN_X",
    "DEFAULT_VULN_FAIL_PCT", "DEFAULT_VULN_WARN_PCT",
    "BaselineRefreshDecision",
    "StressDiff", "StressResult",
    "compare_to_baseline", "configure_sweep_logging",
    "confirm_elapsed_regressions",
    "decide_baseline_refresh",
    "run_sweep_and_report",
    "diffs_to_exit_code",
    "render_diffs", "run_stress_sweep", "write_baseline",
]

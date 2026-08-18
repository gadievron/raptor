"""Bounded-concurrency executor for /audit review tasks.

Drives ``review_one_function()`` through a ``TaskGraph``, running up to
``max_workers`` reviews concurrently.  Taint summaries are published
after each completion, unlocking dependent tasks automatically.

When ``max_workers=1`` the execution is serial and deterministic — the
same order as the current loop.  Higher values enable LLM-call overlap
at the cost of non-deterministic observation ordering.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from core.llm.client import is_budget_exceeded_error
from core.llm.concurrency import read_throttle_cooldown_s

logger = logging.getLogger(__name__)


@dataclass
class ExecutorConfig:
    max_workers: int = 1


_PROGRESS_CHECKPOINT_INTERVAL = 60.0


@dataclass
class ExecutorStats:
    dispatched: int = 0
    completed: int = 0
    repass_completed: int = 0
    budget_stopped: bool = False
    wall_time_s: float = 0.0

    def to_dict(self) -> dict:
        return {
            "dispatched": self.dispatched,
            "completed": self.completed,
            "repass_completed": self.repass_completed,
            "budget_stopped": self.budget_stopped,
            "wall_time_s": round(self.wall_time_s, 1),
        }


def run_executor_sync(
    graph: Any,
    review_fn: Callable,
    shared: Any,
    config: Any,
    result: Any,
    executor_config: ExecutorConfig | None = None,
    *,
    joern_server: Any | None = None,
    audit_log: list[dict[str, Any]] | None = None,
    workqueue: list[dict[str, Any]] | None = None,
    reviewed_set: set[str] | None = None,
    start_time: float = 0.0,
    layer_disagreements: list[Any] | None = None,
    on_progress: Callable | None = None,
    collector: Any | None = None,
    budget_check: Callable[[], bool] | None = None,
    review_one_fn: Callable | None = None,
    on_tick: Callable[[dict[str, Any]], None] | None = None,
    reviewed_outcomes: dict[str, Any] | None = None,
    throttle: Any | None = None,
    study_queue: Any | None = None,
    concept_index_ref: list | None = None,
) -> ExecutorStats:
    """Executor entry point — drop-in replacement for the old ``for gap`` loop.

    With ``max_workers == 1`` (default) tasks are consumed from *graph*
    in topological order one at a time, serially and deterministically.
    When ``executor_config.max_workers > 1`` this transparently
    dispatches to the bounded-concurrency async path (``_run_async``)
    on a private event loop.

    *on_tick* is called once per iteration with the current gap, before
    the review function runs.  The orchestrator uses it for Joern
    future draining and ``reviewed_before_joern`` bookkeeping.
    """
    if review_one_fn is None:
        from .orchestrator import review_one_function
        review_one_fn = review_one_function

    ec = executor_config or ExecutorConfig()
    stats = ExecutorStats()
    wall_start = time.monotonic()
    review_idx = 0
    total = len(graph)

    if ec.max_workers > 1:
        logger.info(
            "parallel executor: max_workers=%d (async path)",
            ec.max_workers,
        )
        loop = asyncio.new_event_loop()
        try:
            stats = loop.run_until_complete(
                _run_async(
                    graph, review_fn, shared, config, result,
                    ec,
                    joern_server=joern_server,
                    audit_log=audit_log,
                    workqueue=workqueue,
                    reviewed_set=reviewed_set,
                    start_time=start_time,
                    layer_disagreements=layer_disagreements,
                    on_progress=on_progress,
                    collector=collector,
                    budget_check=budget_check,
                    review_one_fn=review_one_fn,
                    on_tick=on_tick,
                    reviewed_outcomes=reviewed_outcomes,
                    throttle=throttle,
                    study_queue=study_queue,
                    concept_index_ref=concept_index_ref,
                ),
            )
        finally:
            loop.close()
        return stats

    glance_batch: list[Any] = []
    batch_review_fn = _get_batch_review_fn(shared, config)

    def _flush_glance_batch() -> bool:
        """Flush queued glance tasks.  Returns True when the batch hit
        budget exhaustion — the caller must stop the run gracefully
        (the same handling direct review calls get) instead of letting
        the RuntimeError abort before ``collector.flush()``."""
        nonlocal review_idx
        if not glance_batch or batch_review_fn is None:
            return False
        try:
            _process_glance_batch(
                glance_batch, batch_review_fn, shared, config,
                result, review_one_fn, review_fn,
                joern_server=joern_server,
                audit_log=audit_log,
                workqueue=workqueue,
                reviewed_set=reviewed_set,
                start_time=start_time,
                layer_disagreements=layer_disagreements,
                on_progress=on_progress,
                review_idx=review_idx,
                total=total,
                collector=collector,
                graph=graph,
                reviewed_outcomes=reviewed_outcomes,
            )
        except RuntimeError as exc:
            if not is_budget_exceeded_error(exc):
                raise
            stats.budget_stopped = True
            result.terminated_by = "llm_budget_exceeded"
            glance_batch.clear()
            return True
        for t in glance_batch:
            graph.mark_complete(t.key)
            stats.completed += 1
            review_idx += 1
        glance_batch.clear()
        return False

    from .orchestrator import _update_run_progress, is_shutdown_requested
    last_checkpoint = time.monotonic()

    while graph.pending > 0:
        if budget_check and budget_check():
            _flush_glance_batch()
            stats.budget_stopped = True
            break

        if is_shutdown_requested():
            _flush_glance_batch()
            stats.budget_stopped = True
            break

        tasks = graph.pop_ready(1)
        if not tasks:
            _flush_glance_batch()
            if graph.pending > 0:
                logger.warning(
                    "executor: no ready tasks but %d pending — cycle?",
                    graph.pending,
                )
            break

        task = tasks[0]
        stats.dispatched += 1

        if (
            batch_review_fn
            and _is_glance(task, shared)
            and not task.gap.get("force_review")
        ):
            glance_batch.append(task)
            if (
                len(glance_batch) >= _GLANCE_BATCH_SIZE
                and _flush_glance_batch()
            ):
                break
            continue

        if _flush_glance_batch():
            break

        if on_tick:
            on_tick(task.gap)

        try:
            review_one_fn(
                task.gap, shared, config, review_fn, result,
                joern_server=joern_server,
                audit_log=audit_log,
                workqueue=workqueue,
                reviewed_set=reviewed_set,
                start_time=start_time,
                layer_disagreements=layer_disagreements,
                on_progress=on_progress,
                review_idx=review_idx,
                total=total,
                collector=collector,
                graph=graph,
                reviewed_outcomes=reviewed_outcomes,
            )
        except RuntimeError as exc:
            if is_budget_exceeded_error(exc):
                stats.budget_stopped = True
                result.terminated_by = "llm_budget_exceeded"
                break
            raise

        graph.mark_complete(task.key)
        stats.completed += 1
        review_idx += 1

        now = time.monotonic()
        if now - last_checkpoint >= _PROGRESS_CHECKPOINT_INTERVAL:
            _update_run_progress(config.out_dir, result)
            last_checkpoint = now

    _flush_glance_batch()

    repass = graph.repass_tasks()
    if repass and not stats.budget_stopped:
        logger.info(
            "cycle repass: re-reviewing %d functions with full callee context",
            len(repass),
        )
        for task in repass:
            if is_shutdown_requested():
                stats.budget_stopped = True
                break
            if budget_check and budget_check():
                stats.budget_stopped = True
                break
            if on_tick:
                on_tick(task.gap)
            try:
                review_one_fn(
                    task.gap, shared, config, review_fn, result,
                    joern_server=joern_server,
                    audit_log=audit_log,
                    workqueue=workqueue,
                    reviewed_set=reviewed_set,
                    start_time=start_time,
                    layer_disagreements=layer_disagreements,
                    on_progress=on_progress,
                    review_idx=review_idx,
                    total=total,
                    collector=collector,
                    graph=graph,
                    reviewed_outcomes=reviewed_outcomes,
                )
            except RuntimeError as exc:
                if is_budget_exceeded_error(exc):
                    stats.budget_stopped = True
                    result.terminated_by = "llm_budget_exceeded"
                    break
                raise
            stats.repass_completed += 1
            review_idx += 1

    stats.wall_time_s = time.monotonic() - wall_start
    return stats


async def _run_async(
    graph: Any,
    review_fn: Callable,
    shared: Any,
    config: Any,
    result: Any,
    ec: ExecutorConfig,
    *,
    joern_server: Any | None = None,
    audit_log: list[dict[str, Any]] | None = None,
    workqueue: list[dict[str, Any]] | None = None,
    reviewed_set: set[str] | None = None,
    start_time: float = 0.0,
    layer_disagreements: list[Any] | None = None,
    on_progress: Callable | None = None,
    collector: Any | None = None,
    budget_check: Callable[[], bool] | None = None,
    review_one_fn: Callable | None = None,
    on_tick: Callable[[dict[str, Any]], None] | None = None,
    reviewed_outcomes: dict[str, Any] | None = None,
    throttle: Any | None = None,
    study_queue: Any | None = None,
    concept_index_ref: list | None = None,
) -> ExecutorStats:
    """Async executor with bounded concurrency via throttle.

    Glance-tier tasks are accumulated and submitted in batches of
    ``_GLANCE_BATCH_SIZE`` — each batch is a single LLM call covering
    multiple functions.  Non-glance tasks get individual LLM calls.
    Both kinds run concurrently, bounded by the throttle.

    When *throttle* is provided externally (shared with other
    consumers like the study thread), it is used as-is and NOT
    closed on exit — the caller owns its lifecycle.
    """
    if review_one_fn is None:
        from .orchestrator import review_one_function
        review_one_fn = review_one_function

    from core.llm.throttle import AdaptiveThrottle

    owns_throttle = throttle is None
    if owns_throttle:
        cooldown = read_throttle_cooldown_s()
        throttle = AdaptiveThrottle(ec.max_workers, cooldown_s=cooldown)
    try:
        return await _run_async_body(
            graph, review_fn, shared, config, result, ec, throttle,
            joern_server=joern_server,
            audit_log=audit_log,
            workqueue=workqueue,
            reviewed_set=reviewed_set,
            start_time=start_time,
            layer_disagreements=layer_disagreements,
            on_progress=on_progress,
            collector=collector,
            budget_check=budget_check,
            review_one_fn=review_one_fn,
            on_tick=on_tick,
            reviewed_outcomes=reviewed_outcomes,
            study_queue=study_queue,
            concept_index_ref=concept_index_ref,
        )
    finally:
        if throttle.signal_count:
            logger.info(
                "throttle stats: %d 429 signals, final effective=%d/%d",
                throttle.signal_count, throttle.effective_workers,
                throttle.max_workers,
            )
        if owns_throttle:
            throttle.close()


async def _run_async_body(
    graph: Any,
    review_fn: Callable,
    shared: Any,
    config: Any,
    result: Any,
    ec: ExecutorConfig,
    throttle: Any,
    *,
    joern_server: Any | None = None,
    audit_log: list[dict[str, Any]] | None = None,
    workqueue: list[dict[str, Any]] | None = None,
    reviewed_set: set[str] | None = None,
    start_time: float = 0.0,
    layer_disagreements: list[Any] | None = None,
    on_progress: Callable | None = None,
    collector: Any | None = None,
    budget_check: Callable[[], bool] | None = None,
    review_one_fn: Callable | None = None,
    on_tick: Callable[[dict[str, Any]], None] | None = None,
    reviewed_outcomes: dict[str, Any] | None = None,
    study_queue: Any | None = None,
    concept_index_ref: list | None = None,
) -> ExecutorStats:
    """Inner body of the async executor, separated so _run_async can
    wrap it in try/finally for throttle cleanup."""
    from .orchestrator import _update_run_progress, is_shutdown_requested

    stats = ExecutorStats()
    wall_start = time.monotonic()
    last_checkpoint = wall_start
    total = len(graph)
    review_idx_lock = asyncio.Lock()
    review_idx_box = [0]
    inflight: set[asyncio.Task] = set()
    stopping = False

    batch_review_fn = _get_batch_review_fn(shared, config)
    glance_pending: list[Any] = []

    # Suppression gate state
    hold_set: dict[str, set[str]] = {}
    held_tasks: dict[str, Any] = {}
    study_event: asyncio.Event | None = None
    if study_queue is not None:
        study_event = asyncio.Event()
        loop = asyncio.get_event_loop()
        study_queue.set_event_loop(loop, study_event)

    def _should_stop() -> bool:
        nonlocal stopping
        if stopping:
            return True
        if is_shutdown_requested():
            stopping = True
            stats.budget_stopped = True
            return True
        if budget_check and budget_check():
            stopping = True
            stats.budget_stopped = True
            return True
        return False

    def _check_suppression(task: Any) -> bool:
        """Return True if task should be held (suppressed)."""
        if study_queue is None or concept_index_ref is None:
            return False
        ci = concept_index_ref[0] if concept_index_ref else None
        if ci is None:
            return False
        if graph.has_dependents(task.key):
            return False
        concepts = ci.concepts_for(
            task.gap.get("file", ""), task.gap.get("name", ""),
        )
        if not concepts:
            return False
        pending = study_queue.pending_concepts()
        blocked_by = concepts & pending
        if blocked_by:
            hold_set[task.key] = blocked_by
            held_tasks[task.key] = task
            return True
        return False

    def _release_held() -> list[Any]:
        """Release tasks whose blocking concepts are now studied."""
        if not hold_set:
            return []
        if study_queue is not None and study_queue.consumer_done:
            released = list(held_tasks.values())
            hold_set.clear()
            held_tasks.clear()
            return released
        pending = (
            study_queue.pending_concepts()
            if study_queue is not None
            else frozenset()
        )
        released = []
        for key in list(hold_set):
            if not (hold_set[key] & pending):
                hold_set.pop(key)
                released.append(held_tasks.pop(key))
        return released

    def _dispatch_ready(tasks: list[Any]) -> None:
        """Route ready tasks: glance-tier into batch queue, others individual."""
        for task in tasks:
            if _check_suppression(task):
                continue
            if (
                batch_review_fn
                and _is_glance(task, shared)
                and not task.gap.get("force_review")
            ):
                glance_pending.append(task)
                stats.dispatched += 1
            else:
                stats.dispatched += 1
                child = asyncio.create_task(_run_task(task))
                inflight.add(child)
        while len(glance_pending) >= _GLANCE_BATCH_SIZE:
            batch = glance_pending[:_GLANCE_BATCH_SIZE]
            del glance_pending[:_GLANCE_BATCH_SIZE]
            child = asyncio.create_task(_run_batch(batch))
            inflight.add(child)

    async def _after_completion() -> None:
        """Shared post-review work: checkpoint + dispatch newly ready."""
        nonlocal last_checkpoint
        now = time.monotonic()
        if now - last_checkpoint >= _PROGRESS_CHECKPOINT_INTERVAL:
            _update_run_progress(config.out_dir, result)
            last_checkpoint = now
        if _should_stop():
            return
        newly_ready = graph.pop_ready(ec.max_workers)
        _dispatch_ready(newly_ready)

    async def _run_batch(batch_tasks: list[Any]) -> None:
        """Process a group of glance tasks in one LLM call."""
        if _should_stop():
            return
        async with throttle.acquire():
            if _should_stop():
                return
            for task in batch_tasks:
                if on_tick:
                    on_tick(task.gap)
            async with review_idx_lock:
                idx = review_idx_box[0]
                review_idx_box[0] += len(batch_tasks)
            loop = asyncio.get_event_loop()
            try:
                await loop.run_in_executor(
                    None,
                    lambda bt=batch_tasks, ri=idx: _process_glance_batch(
                        bt, batch_review_fn, shared, config,
                        result, review_one_fn, review_fn,
                        joern_server=joern_server,
                        audit_log=audit_log,
                        workqueue=workqueue,
                        reviewed_set=reviewed_set,
                        start_time=start_time,
                        layer_disagreements=layer_disagreements,
                        on_progress=on_progress,
                        review_idx=ri,
                        total=total,
                        collector=collector,
                        graph=graph,
                        reviewed_outcomes=reviewed_outcomes,
                    ),
                )
            except RuntimeError as exc:
                if is_budget_exceeded_error(exc):
                    stats.budget_stopped = True
                    result.terminated_by = "llm_budget_exceeded"
                    return
                raise
            for t in batch_tasks:
                graph.mark_complete(t.key)
                async with review_idx_lock:
                    stats.completed += 1
            await _after_completion()

    async def _run_task(task: Any) -> None:
        if _should_stop():
            return
        async with throttle.acquire():
            if _should_stop():
                return

            if on_tick:
                on_tick(task.gap)

            async with review_idx_lock:
                idx = review_idx_box[0]
                review_idx_box[0] += 1

            loop = asyncio.get_event_loop()
            try:
                await loop.run_in_executor(
                    None,
                    lambda t=task, i=idx: review_one_fn(
                        t.gap, shared, config, review_fn, result,
                        joern_server=joern_server,
                        audit_log=audit_log,
                        workqueue=workqueue,
                        reviewed_set=reviewed_set,
                        start_time=start_time,
                        layer_disagreements=layer_disagreements,
                        on_progress=on_progress,
                        review_idx=i,
                        total=total,
                        collector=collector,
                        graph=graph,
                        reviewed_outcomes=reviewed_outcomes,
                    ),
                )
            except RuntimeError as exc:
                if is_budget_exceeded_error(exc):
                    stats.budget_stopped = True
                    result.terminated_by = "llm_budget_exceeded"
                    return
                raise

            graph.mark_complete(task.key)
            async with review_idx_lock:
                stats.completed += 1
            await _after_completion()

    initial = graph.pop_ready(ec.max_workers)
    _dispatch_ready(initial)

    while inflight or glance_pending or hold_set:
        if _should_stop():
            # Stop requested: drop queued glance batches and held
            # tasks — they stay unreviewed gaps.  Without this the
            # loop reached ``asyncio.wait()`` with an empty inflight
            # set (ValueError) whenever a stop fired while glance
            # tasks were queued and nothing was in flight.
            glance_pending.clear()
            hold_set.clear()
            held_tasks.clear()
            if not inflight:
                break
        elif glance_pending:
            batch = list(glance_pending)
            glance_pending.clear()
            child = asyncio.create_task(_run_batch(batch))
            inflight.add(child)

        # Release held tasks whose blocking concepts are now studied
        released = _release_held()
        if released:
            _dispatch_ready(released)

        if not inflight and not glance_pending:
            if not hold_set:
                break
            # All work is held — wait for study to complete
            if study_event is not None:
                study_event.clear()
                try:
                    await asyncio.wait_for(study_event.wait(), timeout=30.0)
                except asyncio.TimeoutError:
                    pass
                continue
            else:
                break

        done, _pending = await asyncio.wait(
            inflight, return_when=asyncio.FIRST_COMPLETED,
        )
        inflight -= done
        for t in done:
            if not t.cancelled() and t.exception() is not None:
                logger.warning(
                    "unhandled task exception: %s",
                    t.exception(), exc_info=t.exception(),
                )

    repass = graph.repass_tasks()
    if repass and not _should_stop():
        logger.info(
            "cycle repass: re-reviewing %d functions with full callee context",
            len(repass),
        )

        async def _run_repass(task: Any) -> None:
            if _should_stop():
                return
            async with throttle.acquire():
                if _should_stop():
                    return
                if on_tick:
                    on_tick(task.gap)
                async with review_idx_lock:
                    idx = review_idx_box[0]
                    review_idx_box[0] += 1
                loop = asyncio.get_event_loop()
                try:
                    await loop.run_in_executor(
                        None,
                        lambda t=task, i=idx: review_one_fn(
                            t.gap, shared, config, review_fn, result,
                            joern_server=joern_server,
                            audit_log=audit_log,
                            workqueue=workqueue,
                            reviewed_set=reviewed_set,
                            start_time=start_time,
                            layer_disagreements=layer_disagreements,
                            on_progress=on_progress,
                            review_idx=i,
                            total=total,
                            collector=collector,
                            graph=graph,
                            reviewed_outcomes=reviewed_outcomes,
                        ),
                    )
                except RuntimeError as exc:
                    if is_budget_exceeded_error(exc):
                        stats.budget_stopped = True
                        result.terminated_by = "llm_budget_exceeded"
                        return
                    raise
                async with review_idx_lock:
                    stats.repass_completed += 1

        repass_inflight: set[asyncio.Task] = set()
        for task in repass:
            if _should_stop():
                break
            t = asyncio.create_task(_run_repass(task))
            repass_inflight.add(t)
        while repass_inflight:
            done, _rp = await asyncio.wait(
                repass_inflight, return_when=asyncio.FIRST_COMPLETED,
            )
            repass_inflight -= done
            for t in done:
                if not t.cancelled() and t.exception() is not None:
                    logger.warning(
                        "unhandled repass exception: %s",
                        t.exception(), exc_info=t.exception(),
                    )

    stats.wall_time_s = time.monotonic() - wall_start
    return stats


# ── GLANCE batching helpers ───────────────────────────────────────────

_GLANCE_BATCH_SIZE = 10

# Per-run cap on glance-suspicious escalations to full individual
# review. The glance prompt biases toward clean, so suspicious rates
# are low — the cap bounds the worst case (a model that flags
# everything) without starving the common one.
_MAX_GLANCE_ESCALATIONS_PER_RUN = 20


def _escalate_glance_suspicious(task: Any, shared: Any, result: Any) -> bool:
    """Reserve a full individual review for a glance-suspicious function.

    A batch-glance "suspicious" is a ~500-token guess — the model's own
    "this looks wrong" signal — that previously committed directly and
    was never investigated (deepen requires a review body, sweeps fire
    on findings). Escalation upgrades the function's triage bucket to
    INVESTIGATE (so the re-review gets a full context budget), marks
    the gap ``force_review``, and counts against the per-run cap.

    Returns True when the caller should run the full review instead of
    committing the glance outcome; False when the cap is exhausted
    (the glance outcome then commits as before — nothing is lost).
    """
    with result._lock:
        if result.glance_escalated >= _MAX_GLANCE_ESCALATIONS_PER_RUN:
            return False
        result.glance_escalated += 1

    try:
        from .triage import TOKEN_BUDGETS, TriageBucket, TriageResult

        triage_results = getattr(shared, "triage_results", None)
        if triage_results is not None:
            prior = triage_results.get(task.key)
            reasons = tuple(getattr(prior, "reasons", ()) or ())
            triage_results[task.key] = TriageResult(
                bucket=TriageBucket.INVESTIGATE,
                reasons=reasons + (
                    "glance flagged suspicious — escalated to full review",
                ),
                token_budget=TOKEN_BUDGETS[TriageBucket.INVESTIGATE],
                priority_score=getattr(prior, "priority_score", 0.0),
            )
    except Exception:
        logger.debug(
            "triage upgrade failed for %s", task.key, exc_info=True,
        )
    task.gap["force_review"] = True
    return True


def _is_glance(task: Any, shared: Any) -> bool:
    """True when the task is classified as GLANCE by the triage pass."""
    triage_results = getattr(shared, "triage_results", None)
    if not triage_results:
        return False
    tr = triage_results.get(task.key)
    return tr is not None and tr.bucket.value == "glance"


def _get_batch_review_fn(shared: Any, config: Any) -> Any:
    """Try to build a batch review function from the LLM client."""
    try:
        llm_client = getattr(config, "llm_client", None)
        if llm_client is None:
            return None
        from .batch_glance import make_batch_review_fn
        models = getattr(config, "models", None)
        model_name = models[0] if models else None
        # The "default" sentinel means "no explicit model" — passing
        # it through would fail config_for_model resolution and log a
        # spurious warning on every run.
        if model_name == "default":
            model_name = None
        return make_batch_review_fn(llm_client, model_name=model_name)
    except Exception:
        logger.debug("batch glance init failed", exc_info=True)
        return None


def _process_glance_batch(
    tasks: list[Any],
    batch_review_fn: Callable,
    shared: Any,
    config: Any,
    result: Any,
    review_one_fn: Callable,
    review_fn: Callable,
    *,
    joern_server: Any = None,
    audit_log: list | None = None,
    workqueue: list | None = None,
    reviewed_set: set | None = None,
    start_time: float = 0.0,
    layer_disagreements: list | None = None,
    on_progress: Callable | None = None,
    review_idx: int = 0,
    total: int = 0,
    collector: Any = None,
    graph: Any = None,
    reviewed_outcomes: dict[str, Any] | None = None,
) -> None:
    """Process a batch of GLANCE tasks in a single LLM call.

    On batch failure or per-function parse errors, falls back to
    individual ``review_one_fn`` calls for those functions.
    """
    from .orchestrator import _build_context, _commit_outcome, _tally_outcome

    contexts = []
    for task in tasks:
        ctx = _build_context(
            config, task.gap,
            shared.checklist, shared.context_map,
            shared.evidence_index,
        )
        contexts.append(ctx)

    try:
        outcomes = batch_review_fn(contexts, config)
    except Exception as exc:  # noqa: BLE001 — any batch failure falls back to individual reviews
        logger.warning("batch glance failed, falling back: %s", exc)
        outcomes = None

    for i, task in enumerate(tasks):
        if outcomes and i < len(outcomes) and outcomes[i].status != "error":
            outcome = outcomes[i]
            outcome.line = task.gap.get("line_start", 0)

            # ── Glance-suspicious escalation ──────────────────────
            # The model's "this looks wrong" from a 500-token glance is
            # a lead, not a verdict — route it through a FULL
            # individual review instead of committing the guess. The
            # glance outcome is discarded (its verdict is replaced by
            # the full review) but its LLM spend stays on the ledger.
            if (
                outcome.status == "suspicious"
                and _escalate_glance_suspicious(task, shared, result)
            ):
                if outcome.cost_usd:
                    with result._lock:
                        result.total_cost_usd += outcome.cost_usd
                logger.info(
                    "glance flagged %s:%s suspicious — escalating to "
                    "full individual review",
                    outcome.file, outcome.function,
                )
                try:
                    review_one_fn(
                        task.gap, shared, config, review_fn, result,
                        joern_server=joern_server,
                        audit_log=audit_log,
                        workqueue=workqueue,
                        reviewed_set=reviewed_set,
                        start_time=start_time,
                        layer_disagreements=layer_disagreements,
                        on_progress=on_progress,
                        review_idx=review_idx + i,
                        total=total,
                        collector=collector,
                        graph=graph,
                        reviewed_outcomes=reviewed_outcomes,
                    )
                except Exception as exc:
                    if isinstance(exc, RuntimeError) and is_budget_exceeded_error(exc):
                        raise
                    logger.warning(
                        "glance escalation review failed for %s:%s",
                        task.gap.get("file", "?"),
                        task.gap.get("name", "?"),
                        exc_info=True,
                    )
                continue

            # ── Refutation gates (glance batch) ───────────────────
            if outcome.status in ("finding", "suspicious"):
                try:
                    from .refutation import refute_hypothesis

                    rv = refute_hypothesis(
                        outcome,
                        domain_model=getattr(shared, "domain_model", None),
                        checklist=shared.checklist,
                        config=config,
                    )
                    if rv is not None:
                        from .orchestrator import append_audit_log

                        append_audit_log(config.out_dir, {
                            "action": "refutation_gate",
                            "gate": rv.gate,
                            "key": f"{outcome.file}:{outcome.function}:{task.gap.get('line_start', 0)}",
                            "file": outcome.file,
                            "function": outcome.function,
                            "reason": rv.reason,
                            "demote_to": rv.demote_to,
                            "original_status": outcome.status,
                            "applied": True,
                            "batch": True,
                        })
                        from .orchestrator import _demote_outcome

                        outcome = _demote_outcome(
                            outcome, f"[{rv.gate}: {rv.reason}]",
                        )
                        outcome.status = rv.demote_to
                except Exception:
                    logger.debug(
                        "refutation gate error for %s:%s (glance batch)",
                        task.gap.get("file"), task.gap.get("name"),
                        exc_info=True,
                    )

            if collector is not None:
                collector.submit(outcome, task.gap)
            else:
                try:
                    _commit_outcome(config, outcome, task.gap, batch=True)
                except Exception:
                    logger.warning(
                        "commit failed for batch item %s:%s",
                        task.gap["file"], task.gap["name"], exc_info=True,
                    )
            _tally_outcome(result, outcome)
            if on_progress:
                on_progress(review_idx + i, total, outcome)
        else:
            try:
                review_one_fn(
                    task.gap, shared, config, review_fn, result,
                    joern_server=joern_server,
                    audit_log=audit_log,
                    workqueue=workqueue,
                    reviewed_set=reviewed_set,
                    start_time=start_time,
                    layer_disagreements=layer_disagreements,
                    on_progress=on_progress,
                    review_idx=review_idx + i,
                    total=total,
                    collector=collector,
                    graph=graph,
                    reviewed_outcomes=reviewed_outcomes,
                )
            except Exception as exc:
                if isinstance(exc, RuntimeError) and is_budget_exceeded_error(exc):
                    raise
                logger.warning(
                    "glance fallback failed for %s:%s",
                    task.gap.get("file", "?"),
                    task.gap.get("name", "?"),
                    exc_info=True,
                )


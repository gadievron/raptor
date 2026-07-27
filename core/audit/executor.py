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
) -> ExecutorStats:
    """Serial executor — drop-in replacement for the current ``for gap`` loop.

    Consumes tasks from *graph* in topological order one at a time.
    When ``executor_config.max_workers > 1``, use ``run_executor_async``
    instead (not yet implemented).

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
                ),
            )
        finally:
            loop.close()
        return stats

    glance_batch: list[Any] = []
    batch_review_fn = _get_batch_review_fn(shared, config)

    def _flush_glance_batch() -> None:
        nonlocal review_idx
        if not glance_batch or batch_review_fn is None:
            return
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
        )
        for t in glance_batch:
            graph.mark_complete(t.key)
            stats.completed += 1
            review_idx += 1
        glance_batch.clear()

    from .orchestrator import is_shutdown_requested, _update_run_progress
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

        if batch_review_fn and _is_glance(task, shared):
            glance_batch.append(task)
            if len(glance_batch) >= _GLANCE_BATCH_SIZE:
                _flush_glance_batch()
            continue

        _flush_glance_batch()

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
            )
        except RuntimeError as exc:
            if "budget exceeded" in str(exc).lower():
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
                )
            except RuntimeError as exc:
                if "budget exceeded" in str(exc).lower():
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
) -> ExecutorStats:
    """Async executor with bounded concurrency via semaphore.

    Glance-tier tasks are accumulated and submitted in batches of
    ``_GLANCE_BATCH_SIZE`` — each batch is a single LLM call covering
    multiple functions.  Non-glance tasks get individual LLM calls.
    Both kinds run concurrently, bounded by the semaphore.
    """
    if review_one_fn is None:
        from .orchestrator import review_one_function
        review_one_fn = review_one_function

    from core.llm.throttle import AdaptiveThrottle

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
        )
    finally:
        if throttle.signal_count:
            logger.info(
                "throttle stats: %d 429 signals, final effective=%d/%d",
                throttle.signal_count, throttle.effective_workers,
                throttle.max_workers,
            )
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
) -> ExecutorStats:
    """Inner body of the async executor, separated so _run_async can
    wrap it in try/finally for throttle cleanup."""
    from .orchestrator import is_shutdown_requested, _update_run_progress

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

    def _dispatch_ready(tasks: list[Any]) -> None:
        """Route ready tasks: glance-tier into batch queue, others individual."""
        for task in tasks:
            if batch_review_fn and _is_glance(task, shared):
                glance_pending.append(task)
                stats.dispatched += 1
            else:
                stats.dispatched += 1
                child = asyncio.create_task(_run_task(task))
                inflight.add(child)
                child.add_done_callback(inflight.discard)
        while len(glance_pending) >= _GLANCE_BATCH_SIZE:
            batch = glance_pending[:_GLANCE_BATCH_SIZE]
            del glance_pending[:_GLANCE_BATCH_SIZE]
            child = asyncio.create_task(_run_batch(batch))
            inflight.add(child)
            child.add_done_callback(inflight.discard)

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
                    ),
                )
            except RuntimeError as exc:
                if "budget exceeded" in str(exc).lower():
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
                    ),
                )
            except RuntimeError as exc:
                if "budget exceeded" in str(exc).lower():
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

    while True:
        if glance_pending and not _should_stop():
            batch = list(glance_pending)
            glance_pending.clear()
            child = asyncio.create_task(_run_batch(batch))
            inflight.add(child)
            child.add_done_callback(inflight.discard)
        if not inflight:
            break
        results = await asyncio.gather(*inflight, return_exceptions=True)
        for r in results:
            if isinstance(r, BaseException):
                logger.warning("unhandled task exception: %s", r, exc_info=r)

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
                        ),
                    )
                except RuntimeError as exc:
                    if "budget exceeded" in str(exc).lower():
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
            t.add_done_callback(repass_inflight.discard)
        while repass_inflight:
            rp_results = await asyncio.gather(
                *repass_inflight, return_exceptions=True,
            )
            for r in rp_results:
                if isinstance(r, BaseException):
                    logger.warning("unhandled repass exception: %s", r, exc_info=r)

    stats.wall_time_s = time.monotonic() - wall_start
    return stats


# ── GLANCE batching helpers ───────────────────────────────────────────

_GLANCE_BATCH_SIZE = 10


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
    except Exception as exc:
        logger.warning("batch glance failed, falling back: %s", exc)
        outcomes = None

    for i, task in enumerate(tasks):
        if outcomes and i < len(outcomes) and outcomes[i].status != "error":
            outcome = outcomes[i]
            outcome.line = task.gap.get("line_start", 0)
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
                )
            except RuntimeError as exc:
                if "budget exceeded" in str(exc).lower():
                    raise
            except Exception:
                logger.warning(
                    "glance fallback failed for %s:%s",
                    task.gap.get("file", "?"),
                    task.gap.get("name", "?"),
                    exc_info=True,
                )


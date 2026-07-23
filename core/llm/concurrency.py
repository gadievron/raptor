"""LLM concurrency primitives.

Provides ``derive_max_workers()`` for any component that needs to
choose a safe concurrency level for LLM calls, ``run_parallel()``
for fan-out of synchronous LLM work across threads with adaptive
rate-limit backoff, and tuning readers for ``tuning.json`` knobs.

``derive_max_workers`` and the tuning readers previously lived in
``core.audit.executor`` — moved here so non-audit consumers (IRIS,
concepts, dataflow, threat model) can import without a layering
violation.
"""

from __future__ import annotations

import json
import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")

MAX_WORKERS_CAP = 32


def derive_max_workers(model: str) -> int:
    """Derive a safe ``max_workers`` from the model's RPM limit.

    If ``max_llm_workers`` in ``tuning.json`` is set to a number,
    that value is used (still clamped to [1, 32]).  Otherwise
    returns ``rpm // 2`` (headroom for retries) clamped to [1, 32].
    Falls back to 1 when RPM is unknown.
    """
    override = read_tuning_max_llm_workers()
    if override is not None:
        return max(1, min(override, MAX_WORKERS_CAP))

    from core.llm.model_data import rpm_for

    rpm = rpm_for(model)
    if rpm <= 0:
        return 1
    return max(1, min(rpm // 2, MAX_WORKERS_CAP))


def _tuning_path() -> Path:
    return Path(__file__).resolve().parents[2] / "tuning.json"


def _read_tuning() -> dict:
    try:
        import re
        text = _tuning_path().read_text()
        clean = re.sub(r"//.*", "", text)
        return json.loads(clean)
    except Exception:
        return {}


def read_tuning_max_llm_workers() -> int | None:
    """Read ``max_llm_workers`` from tuning.json.  Returns None for
    ``"auto"`` or when the key is absent/unparseable."""
    val = _read_tuning().get("max_llm_workers", "auto")
    if val == "auto":
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return None


def read_throttle_cooldown_s() -> float:
    """Read ``throttle_cooldown_s`` from tuning.json.  Defaults to 30."""
    try:
        return float(_read_tuning().get("throttle_cooldown_s", 30))
    except (ValueError, TypeError):
        return 30.0


def run_parallel(
    items: list[Any],
    fn: Any,
    *,
    max_workers: int | None = None,
    model: str = "",
    label: str = "llm",
    on_error: Any | None = None,
) -> list[T]:
    """Fan out *fn* across *items* on a ThreadPoolExecutor with
    adaptive rate-limit backoff.

    Parameters
    ----------
    items:
        Work units.  Each is passed as the sole argument to *fn*.
    fn:
        ``fn(item) -> T``.  Called from a worker thread — must be
        thread-safe (``LLMClient.generate`` already is).
    max_workers:
        Explicit concurrency cap.  When ``None``, derived from *model*
        via ``derive_max_workers()``.
    model:
        Used to derive ``max_workers`` when not given explicitly.
    label:
        Thread-name prefix for debugging.
    on_error:
        Factory ``on_error(item, exception) -> T | None`` called when
        *fn* raises.  Defaults to ``None`` (the slot is filled with
        ``None``).  Returning a value inserts that value in the result
        list at the item's position.

    Returns
    -------
    list[T]:
        One result per item, positionally matched.  Failed items are
        ``None`` (or whatever *on_error* returned).
    """
    if not items:
        return []

    if max_workers is None:
        max_workers = derive_max_workers(model) if model else 1
    max_workers = max(1, min(max_workers, len(items), MAX_WORKERS_CAP))

    if max_workers <= 1:
        results: list[Any] = []
        for item in items:
            try:
                results.append(fn(item))
            except Exception as exc:
                logger.debug("%s: item failed: %s", label, exc, exc_info=True)
                results.append(on_error(item, exc) if on_error else None)
        return results

    from core.llm.throttle import AdaptiveThrottle

    cooldown = read_throttle_cooldown_s()
    throttle = AdaptiveThrottle(max_workers, cooldown_s=cooldown)

    def _do(idx_item: tuple[int, Any]) -> Any:
        idx, item = idx_item
        with throttle.acquire_sync():
            try:
                return fn(item)
            except Exception as exc:
                logger.debug(
                    "%s: item %d failed: %s", label, idx, exc,
                    exc_info=True,
                )
                return on_error(item, exc) if on_error else None

    try:
        with ThreadPoolExecutor(max_workers=max_workers,
                                thread_name_prefix=label) as pool:
            result = list(pool.map(_do, enumerate(items)))
    finally:
        throttle.close()

    logger.info(
        "%s: %d/%d non-null (throttle: %d signals, concurrency %d→%d)",
        label,
        sum(1 for r in result if r is not None),
        len(items),
        throttle.signal_count,
        throttle.max_workers,
        throttle.effective_workers,
    )
    return result

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

# Concurrency ceiling when the primary model is served by the
# claudecode transport. RPM-derived counts assume an API connection
# per worker; here every worker is a full ``claude`` CLI subprocess
# (multi-second boot, hundreds of MB RSS), and N parallel first
# requests with an identical prompt prefix race the server-side
# prompt cache — each pays the full cache WRITE instead of one
# writing and N-1 reading (measured ~19k tokens / ~$0.25 per miss vs
# ~$0.02 per hit). A small pool keeps the pipeline parallel while the
# cache warms after call one. ``RAPTOR_CC_MAX_WORKERS`` overrides;
# ``tuning.json``'s ``max_llm_workers`` still beats both.
CC_MAX_WORKERS_DEFAULT = 4


def _claudecode_worker_cap() -> int:
    import os
    raw = os.environ.get("RAPTOR_CC_MAX_WORKERS", "")
    try:
        cap = int(raw) if raw else CC_MAX_WORKERS_DEFAULT
    except ValueError:
        logger.warning(
            "RAPTOR_CC_MAX_WORKERS=%r is not an integer — using %d",
            raw, CC_MAX_WORKERS_DEFAULT,
        )
        cap = CC_MAX_WORKERS_DEFAULT
    return max(1, min(cap, MAX_WORKERS_CAP))


# Concurrency ceiling when the primary model routes via Bedrock.
# RPM-derived counts assume the account's quota belongs to this run;
# on Bedrock the quota is per-account-per-region and SHARED — most
# visibly with the operator's own interactive Claude Code session on
# the same account, which a 32-worker analysis burst can 429-starve.
# ``RAPTOR_BEDROCK_MAX_WORKERS`` overrides; ``tuning.json``'s
# ``max_llm_workers`` still beats both.
BEDROCK_MAX_WORKERS_DEFAULT = 8


def _bedrock_worker_cap() -> int:
    import os
    raw = os.environ.get("RAPTOR_BEDROCK_MAX_WORKERS", "")
    try:
        cap = int(raw) if raw else BEDROCK_MAX_WORKERS_DEFAULT
    except ValueError:
        logger.warning(
            "RAPTOR_BEDROCK_MAX_WORKERS=%r is not an integer — using %d",
            raw, BEDROCK_MAX_WORKERS_DEFAULT,
        )
        cap = BEDROCK_MAX_WORKERS_DEFAULT
    return max(1, min(cap, MAX_WORKERS_CAP))


def _is_bedrock_primary(model: str) -> bool:
    """True when *model* is served by the Bedrock provider — same
    detection shape as :func:`_is_claudecode_primary`."""
    try:
        from core.llm.config import _get_default_primary_model
        mc = _get_default_primary_model()
    except Exception:  # noqa: BLE001 — config probing is best-effort
        return False
    if mc is None or mc.provider != "bedrock":
        return False
    return model in ("default", mc.model_name)


def _is_claudecode_primary(model: str) -> bool:
    """True when *model* is served by the claudecode transport.

    The pinned model name is a real backend id (indistinguishable
    from an API-served one), so the transport is detected via the
    configured primary provider — same import ``resolve_model_name``
    already uses for ``"default"``.
    """
    try:
        from core.llm.config import _get_default_primary_model
        mc = _get_default_primary_model()
    except Exception:  # noqa: BLE001 — config probing is best-effort
        return False
    if mc is None or mc.provider != "claudecode":
        return False
    return model in ("default", "session-default", mc.model_name)


def derive_max_workers(model: str) -> int:
    """Derive a safe ``max_workers`` from the model's RPM limit.

    If ``max_llm_workers`` in ``tuning.json`` is set to a number,
    that value is used (still clamped to [1, 32]).  Otherwise
    returns ``rpm // 2`` (headroom for retries) clamped to [1, 32]
    — and additionally clamped to the claudecode subprocess ceiling
    when the primary model is served by the CLI transport.
    Falls back to 1 when RPM is unknown.

    ``"default"`` is resolved to the actual primary model inside
    ``rpm_for`` so callers need not resolve it themselves.
    """
    override = read_tuning_max_llm_workers()
    if override is not None:
        return max(1, min(override, MAX_WORKERS_CAP))

    from core.llm.model_data import rpm_for

    rpm = rpm_for(model)
    if rpm <= 0:
        # RPM unknown. For the claudecode transport this is the COMMON
        # case, not the exception: the session-default sentinel (and any
        # backend id the limits table doesn't know) resolves to rpm=0,
        # and the old blanket "fall back to 1" serialized the entire
        # review loop even though the transport comfortably sustains
        # its subprocess ceiling. Use the claudecode worker cap as the
        # floor there; every other unknown model keeps the conservative
        # serial fallback.
        if _is_claudecode_primary(model):
            return _claudecode_worker_cap()
        return 1
    workers = max(1, min(rpm // 2, MAX_WORKERS_CAP))
    if _is_claudecode_primary(model):
        workers = min(workers, _claudecode_worker_cap())
    if _is_bedrock_primary(model):
        # Bedrock quota is per-account-per-region and shared (most
        # visibly with the operator's live Claude Code session) —
        # RPM headroom alone over-provisions.
        workers = min(workers, _bedrock_worker_cap())
    return workers


def warm_claudecode_probe() -> str | None:
    """Warm the cc-probe cache at run start (best-effort, non-fatal).

    ``derive_max_workers`` and model pinning both key on the
    backend-resolved model identity, which is only knowable from a
    real ``claude -p`` call (``probe_cc_session_model``). When the
    probe cache is cold, every consumer falls back to the
    session-default sentinel for the whole run. One tiny probe call
    here (disk-cached for 24h, so usually a no-op) resolves it
    before any workers are derived or dispatched.

    Guards:

    * skipped under pytest (``PYTEST_CURRENT_TEST``) — tests must
      never trigger a live LLM call;
    * skipped when ``RAPTOR_CC_PROBE_WARM=0`` (operator opt-out);
    * skipped when the primary model is not served by the claudecode
      transport (nothing to probe);
    * any failure is swallowed and logged at DEBUG — a dead probe
      must not fail the run (the transport's own error paths report
      real dispatch failures).

    Returns the resolved model id, or ``None`` when skipped/failed.
    """
    import os
    if "PYTEST_CURRENT_TEST" in os.environ:
        return None
    if os.environ.get("RAPTOR_CC_PROBE_WARM", "") == "0":
        return None
    try:
        if not _is_claudecode_primary("default"):
            return None
        from core.llm.cc_probe import probe_cc_session_model
        model = probe_cc_session_model()
        if model:
            logger.debug("cc-probe warm: resolved model %s", model)
        return model
    except Exception:  # warm is strictly best-effort
        logger.debug("cc-probe warm failed", exc_info=True)
        return None


def _tuning_path() -> Path:
    return Path(__file__).resolve().parents[2] / "tuning.json"


def _strip_json_line_comments(text: str) -> str:
    """Strip ``//`` line comments while respecting double-quoted strings."""
    lines = []
    for line in text.split("\n"):
        in_str = False
        i = 0
        while i < len(line):
            c = line[i]
            if c == "\\" and in_str:
                i += 2
                continue
            if c == '"':
                in_str = not in_str
            elif c == "/" and not in_str and i + 1 < len(line) and line[i + 1] == "/":
                line = line[:i]
                break
            i += 1
        lines.append(line)
    return "\n".join(lines)


def _read_tuning() -> dict:
    try:
        text = _tuning_path().read_text()
        clean = _strip_json_line_comments(text)
        return json.loads(clean)
    except Exception:  # noqa: BLE001 — tuning.json is optional
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
        final_effective = throttle.effective_workers
        final_signals = throttle.signal_count
        throttle.close()

    logger.info(
        "%s: %d/%d non-null (throttle: %d signals, concurrency %d→%d)",
        label,
        sum(1 for r in result if r is not None),
        len(items),
        final_signals,
        throttle.max_workers,
        final_effective,
    )
    return result

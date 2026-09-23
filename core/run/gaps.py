"""Analysis-gap trail — durable, loud records for files analysis gave
up on.

When a parser abandons a file — a parse budget expired, an exception
class escaped a parser's own catch, a pooled worker stalled — the
pipeline survives, but until now nothing durable said "this file was
never analysed": the file simply dropped out of the inventory /
dependency set / detector pass. That inverts the security posture: a
crafted input that defeats a parser removes ITSELF from analysis,
invisibly. This module is the single writer for the run-scoped
``analysis-gaps.jsonl`` trail that makes such gaps visible — one JSON
line per abandoned file, counted into run summaries and reports.

Contract (mirrors ``suppressions.jsonl`` / ``promotion-alarms.jsonl``):

- **Loud**: every gap emits a WARNING log even when no run directory
  is resolvable. A gap is never debug-level.
- **Durable**: records append to ``<run_dir>/analysis-gaps.jsonl`` via
  :func:`core.json.jsonl.append_jsonl` (O_APPEND line-atomicity,
  O_NOFOLLOW against a symlink planted in the sandbox-writable run
  dir).
- **Never load-bearing**: persistence failures are logged and
  swallowed; analysis behaviour never depends on the trail.
- **Flood-bounded**: hostile repos can be salted with thousands of
  parser-defeating files. Both the trail and the log stream are
  capped per process (:data:`MAX_GAPS_PER_PROCESS`) with a single
  boundary warning, and every content-derived field is length-capped
  and escaped before persisting — the trail itself must not become
  the DoS.

Multiprocessing: the run-dir pointer
(:func:`core.sandbox.summary.get_active_run_dir`) is a module global
that pool workers do not reliably inherit. Records emitted where no
run dir resolves land in a bounded in-process pending buffer; callers
that own a transport back to the parent (the inventory worker result
dict) drain it with :func:`drain_pending_gaps` and the parent
persists via :func:`persist_gap_records`.
"""

from __future__ import annotations

import contextlib
import logging
import threading
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterator

logger = logging.getLogger(__name__)

GAPS_FILE = "analysis-gaps.jsonl"
GAP_EVENT = "analysis-gap"
# Terminal truncation records: once the per-process cap is reached,
# doubling-milestone records (suppressed = 1, 2, 4, 8, ...) keep the
# TRAIL saying that suppression is happening and how much (the last
# milestone is a lower bound on the true count) — post-cap evasion
# stays visible in the artifact, not only in one log line, while the
# milestone schedule keeps the truncation trail itself flood-bounded
# (log2 growth).
GAP_TRUNCATION_EVENT = "analysis-gap-truncation"

# Digest-attributed records (no parse_origin in scope) describe
# CONTENT, and several parse sites see the same hostile content per
# file (extraction, call graph, lexical witnesses) — without dedupe
# one crafted file writes the same digest record several times over.
# Path-attributed records are NOT deduped: the path names a distinct
# file each time and reason/tool multiplicity is meaningful there.
_UNATTRIBUTED_PREFIX = "<unattributed "
_SEEN_MAX = 4096

# Per-process record cap. Raising it costs disk and report noise on
# adversarial trees; lowering it hides distinct gap records on large
# legitimate runs. 1000 keeps the trail readable while comfortably
# covering non-adversarial runs (a run that abandons 1000+ files has
# a systemic problem the boundary warning states outright).
MAX_GAPS_PER_PROCESS = 1000

# Bounded pending buffer for out-of-run contexts (pool workers, bare
# library calls). Small on purpose: one worker processes one file at
# a time, so anything beyond a handful per drain means a runaway.
_PENDING_MAX = 200

# Length caps for content-derived fields — a hostile repo controls
# file names and the text inside parser error messages.
_FILE_PATH_MAX = 1024
_REASON_MAX = 200
_TOOL_MAX = 64
_DETAIL_MAX = 500
_EXTRA_KEYS_MAX = 16
_EXTRA_VAL_MAX = 500

_lock = threading.Lock()
_gap_count = 0
_suppressed = 0
_pending: list[dict[str, Any]] = []
_seen_digests: set[tuple[str, str]] = set()

# Ambient attribution: parse chokepoints (core.inventory._ts_cache)
# see content, not paths. Per-file loops that know the path set this
# so a chokepoint-emitted gap record can name the file.
_parse_origin: ContextVar[str | None] = ContextVar(
    "raptor_parse_origin", default=None,
)


@contextlib.contextmanager
def parse_origin(path: str | Path) -> "Iterator[None]":
    """Attribute chokepoint-emitted gap records inside the block to
    *path*. Contextvar-backed: thread- and asyncio-safe, and nested
    blocks restore the outer origin on exit."""
    token = _parse_origin.set(str(path))
    try:
        yield
    finally:
        _parse_origin.reset(token)


def current_parse_origin() -> str | None:
    """The file path the surrounding analysis loop declared, if any."""
    return _parse_origin.get()


def _clean(value: object, limit: int) -> str:
    """Length-cap then escape a content-derived string field."""
    from core.security.log_sanitisation import escape_nonprintable
    text = str(value)
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return escape_nonprintable(text)


def build_gap_record(
    *,
    file_path: str,
    reason: str,
    tool: str,
    detail: str = "",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build one gap record (additive schema — consumers must
    tolerate unknown keys, the ``suppressions.jsonl`` rule)."""
    record: dict[str, Any] = {
        "event": GAP_EVENT,
        "ts": datetime.now(timezone.utc).isoformat(),
        "file_path": _clean(file_path, _FILE_PATH_MAX),
        "reason": _clean(reason, _REASON_MAX),
        "tool": _clean(tool, _TOOL_MAX),
        "detail": _clean(detail, _DETAIL_MAX),
    }
    for key, value in list((extra or {}).items())[:_EXTRA_KEYS_MAX]:
        k = _clean(key, 100)
        if k in record:
            continue
        record[k] = (
            value if isinstance(value, (int, float, bool))
            else _clean(value, _EXTRA_VAL_MAX)
        )
    return record


def _register_one() -> tuple[bool, bool]:
    """Count one gap against the process cap.

    Returns ``(within_cap, is_boundary)``; increments under the lock
    so the boundary warning fires exactly once (same reasoning as the
    sandbox denial counter: ``+= 1`` is not atomic in CPython and a
    lost update can skip the one log line announcing the cap).
    """
    global _gap_count
    with _lock:
        _gap_count += 1
        count = _gap_count
    return count <= MAX_GAPS_PER_PROCESS, count == MAX_GAPS_PER_PROCESS + 1


def _note_suppressed(out_dir: Path | None) -> None:
    """Account one record suppressed past the cap.

    The first suppression logs the boundary warning; doubling
    milestones (1, 2, 4, ...) append a durable truncation record so
    the trail itself states that — and roughly how much —
    suppression happened.
    """
    global _suppressed
    with _lock:
        _suppressed += 1
        count = _suppressed
    if count == 1:
        logger.warning(
            "analysis-gap cap reached (%d this process); further "
            "gaps are dropped from the trail and the log. "
            "Adversarial target or systemic parser failure?",
            MAX_GAPS_PER_PROCESS,
        )
    if count & (count - 1):
        return  # not a power of two — no milestone record
    record = {
        "event": GAP_TRUNCATION_EVENT,
        "ts": datetime.now(timezone.utc).isoformat(),
        "cap": MAX_GAPS_PER_PROCESS,
        "suppressed": count,
    }
    if out_dir is None:
        from core.sandbox.summary import get_active_run_dir
        out_dir = get_active_run_dir()
    if out_dir is None:
        with _lock:
            if len(_pending) < _PENDING_MAX:
                _pending.append(record)
        return
    _append(Path(out_dir), record)


def _append(out_dir: Path, record: dict[str, Any]) -> bool:
    from core.json.jsonl import append_jsonl
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        append_jsonl(out_dir / GAPS_FILE, record, sort_keys=True)
    except (OSError, TypeError, ValueError):
        logger.debug(
            "analysis-gap trail write failed under %s", out_dir,
            exc_info=True,
        )
        return False
    return True


def record_analysis_gap(
    out_dir: Path | None = None,
    *,
    file_path: str,
    reason: str,
    tool: str,
    detail: str = "",
    extra: dict[str, Any] | None = None,
) -> bool:
    """Record that analysis abandoned *file_path*.

    Logs a WARNING always. Appends to ``analysis-gaps.jsonl`` under
    *out_dir* (or the active run dir when *out_dir* is None); with
    neither resolvable the record lands in the bounded pending buffer
    for a caller-owned transport. Returns True only when the record
    was persisted to a trail file.
    """
    record = build_gap_record(
        file_path=file_path, reason=reason, tool=tool,
        detail=detail, extra=extra,
    )
    if out_dir is None:
        from core.sandbox.summary import get_active_run_dir
        out_dir = get_active_run_dir()
    dedupe_key: tuple[str, str] | None = None
    if record["file_path"].startswith(_UNATTRIBUTED_PREFIX):
        dedupe_key = (
            str(out_dir) if out_dir is not None else "<pending>",
            record["file_path"],
        )
        with _lock:
            if dedupe_key in _seen_digests:
                logger.debug(
                    "analysis gap: duplicate digest record skipped "
                    "(%s)", record["file_path"],
                )
                return False
    within_cap, _ = _register_one()
    if not within_cap:
        _note_suppressed(Path(out_dir) if out_dir is not None else None)
        return False
    logger.warning(
        "analysis gap: %s NOT analysed by %s — %s%s",
        record["file_path"], record["tool"], record["reason"],
        f" ({record['detail']})" if record["detail"] else "",
    )
    if dedupe_key is not None:
        with _lock:
            if len(_seen_digests) < _SEEN_MAX:
                _seen_digests.add(dedupe_key)
    if out_dir is None:
        with _lock:
            if len(_pending) < _PENDING_MAX:
                _pending.append(record)
        return False
    return _append(Path(out_dir), record)


def drain_pending_gaps() -> list[dict[str, Any]]:
    """Pop and return records buffered where no run dir resolved
    (worker → parent transport)."""
    global _pending
    with _lock:
        drained, _pending = _pending, []
    return drained


def persist_gap_records(
    records: list[dict[str, Any]],
    out_dir: Path | None = None,
) -> int:
    """Parent-side re-emit of drained worker records. Returns the
    number persisted. Records were built by :func:`build_gap_record`
    in the worker but crossed a process boundary — shape-check and
    drop anything that is not a gap record."""
    if out_dir is None:
        from core.sandbox.summary import get_active_run_dir
        out_dir = get_active_run_dir()
    persisted = 0
    for record in records:
        if not isinstance(record, dict):
            continue
        event = record.get("event")
        if event == GAP_TRUNCATION_EVENT:
            # Worker-side truncation milestones stay on the trail too.
            if out_dir is not None and _append(Path(out_dir), record):
                persisted += 1
            continue
        if event != GAP_EVENT:
            continue
        within_cap, _ = _register_one()
        if not within_cap:
            _note_suppressed(Path(out_dir) if out_dir is not None else None)
            continue
        if out_dir is not None and _append(Path(out_dir), record):
            persisted += 1
    return persisted


def load_gaps(out_dir: Path) -> list[dict[str, Any]]:
    """Read a run's gap trail back (best-effort, byte-budgeted — the
    run dir is sandbox-writable, so the trail is read like any other
    run artifact: skeptically)."""
    from core.json.jsonl import load_jsonl
    records = load_jsonl(
        Path(out_dir) / GAPS_FILE,
        max_line_bytes=64 * 1024,
        max_total_bytes=32 * 1024 * 1024,
    )
    return [
        r for r in records
        if isinstance(r, dict) and r.get("event") == GAP_EVENT
    ]


def gap_summary(out_dir: Path) -> dict[str, int]:
    """Per-reason counts for run summaries: ``{reason: count}``.

    When the trail carries truncation records, the summary includes a
    ``"suppressed past cap"`` entry with the highest recorded
    milestone (a lower bound on the true suppressed count) so every
    surfacing path states that the trail is incomplete.
    """
    from core.json.jsonl import load_jsonl
    counts: dict[str, int] = {}
    suppressed = 0
    records = load_jsonl(
        Path(out_dir) / GAPS_FILE,
        max_line_bytes=64 * 1024,
        max_total_bytes=32 * 1024 * 1024,
    )
    for record in records:
        if not isinstance(record, dict):
            continue
        event = record.get("event")
        if event == GAP_EVENT:
            reason = str(record.get("reason", "unknown"))
            counts[reason] = counts.get(reason, 0) + 1
        elif event == GAP_TRUNCATION_EVENT:
            value = record.get("suppressed")
            if isinstance(value, int):
                suppressed = max(suppressed, value)
    if suppressed:
        counts["suppressed past cap"] = suppressed
    return counts

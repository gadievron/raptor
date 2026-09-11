"""Pool pruning — keep N most recent per dedup bucket.

Implementation-time
tuning item #2: "LabeledAttempt deduplication — hash by
(finding_id, exploit_code_sha, model); keep N most recent per bucket.
N = 5 to start."

Without this the pool grows unbounded. Operators running /exploit
repeatedly on the same finding accumulate one record per attempt
forever, even when the model + exploit code are identical.

Pruning is **explicit** — not automatic on write. The store's atomic-
append discipline is the simpler invariant; an opt-in pruner runs
periodically (cron / CLI / before each run, as the operator chooses).

Bucket key: ``(finding_id, exploit_code_sha, model)`` after the plan.
That deliberately allows multiple records per finding when the model
or the exploit text differ (different prompt versions, different
attack shapes). Two identical attempts by the same model collapse
together.

For records with no exploit code (CodeQL adjudications, web records),
the bucket key uses an empty string for the code SHA — operators
typically annotate those via :func:`set_failure_mode` rather than
re-fire, so they don't accumulate the way sandbox records do.
"""

from __future__ import annotations

import hashlib
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone

from core.json import load_json

from .store import project_pool_path
from .types import LabeledAttempt
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

__all__ = ["PruneReport", "prune_pool"]

_log = logging.getLogger(__name__)


# Default N — keeps 5 most recent records per dedup bucket. Per the
# plan: "N = 5 to start." Tuned later from real-target dogfood data.
_DEFAULT_N = 5


@dataclass(frozen=True)
class PruneReport:
    """Statistics from one prune pass."""

    records_seen: int = 0
    buckets: int = 0
    records_kept: int = 0
    records_removed: int = 0
    removed_paths: tuple[Path, ...] = field(default_factory=tuple)


def _bucket_key(record: LabeledAttempt) -> tuple[str, str, str]:
    """``(finding_id, exploit_code_sha, model)`` per the plan."""
    sb = record.sandbox_evidence
    if sb is not None and sb.exploit_code:
        code_sha = hashlib.sha256(
            sb.exploit_code.encode("utf-8"),
        ).hexdigest()
    else:
        code_sha = ""        # CodeQL / web records bucket together by id
    return (
        record.finding_id,
        code_sha,
        record.producing_model,
    )


def _record_ts(record: LabeledAttempt) -> float:
    """ISO-8601 → POSIX timestamp. Records produced by the bridge are
    always parseable (validated at construction).

    Naive timestamps are interpreted as UTC — the same rule
    ``retrieval._record_age_days`` applies — so a bucket mixing naive
    (legacy writer) and aware records orders the same on every host;
    letting ``timestamp()`` apply the LOCAL zone to naive values would
    skew them by the UTC offset and prune the wrong victim.
    """
    ts = datetime.fromisoformat(record.timestamp)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.timestamp()


def prune_pool(
    project_dir: Path,
    *,
    n_per_bucket: int = _DEFAULT_N,
    dry_run: bool = False,
) -> PruneReport:
    """Prune the per-project pool, keeping ``n_per_bucket`` most recent
    records per ``(finding_id, exploit_code_sha, model)`` bucket.

    Reads records directly from the on-disk pool (not via
    :func:`read_all`) so it can correlate each record back to its
    file path for deletion. Records that fail to load are skipped
    silently — same defensive read discipline as the rest of the
    store.

    ``dry_run`` lists what *would* be removed without touching disk.

    Returns a :class:`PruneReport`. Operators wire it into their own
    cron / CLI; nothing in the core path calls this automatically.
    """
    pool = project_pool_path(project_dir)
    if not pool.exists():
        return PruneReport()

    # (record, path, timestamp) tuples grouped by bucket key.
    buckets: dict[tuple[str, str, str], list[tuple[LabeledAttempt, Path, float]]] = {}
    seen = 0
    for sig_dir in sorted(pool.iterdir()):
        if not sig_dir.is_dir():
            continue
        for path in sorted(sig_dir.glob("*.json")):
            blob = load_json(path, max_bytes=8 * 1024 * 1024)
            if blob is None:
                continue
            try:
                rec = LabeledAttempt.from_dict(blob)
            except (ValueError, KeyError, TypeError, OSError, AttributeError):
                # Same skip discipline as store._iter_records_in_dir:
                # AttributeError covers valid JSON of the wrong shape
                # (top-level array, non-dict sub-object) — one bad
                # record must not abort the whole prune.
                _log.debug(
                    "skipping unreadable record %s", path, exc_info=True,
                )
                continue
            seen += 1
            buckets.setdefault(_bucket_key(rec), []).append(
                (rec, path, _record_ts(rec)),
            )

    removed: list[Path] = []
    kept = 0
    for entries in buckets.values():
        # Most recent first; keep the head of the list, remove the tail.
        entries.sort(key=lambda triple: triple[2], reverse=True)
        kept += min(len(entries), n_per_bucket)
        for _rec, path, _ts in entries[n_per_bucket:]:
            removed.append(path)
            if not dry_run:
                try:
                    os.unlink(path)
                except OSError:
                    # Defensive: another process raced us. Continue
                    # rather than aborting the whole prune.
                    pass

    # Tidy up any signature-dirs that are now empty after the prune.
    if not dry_run:
        for sig_dir in pool.iterdir():
            if sig_dir.is_dir() and not any(sig_dir.iterdir()):
                try:
                    sig_dir.rmdir()
                except OSError:
                    pass

    return PruneReport(
        records_seen=seen,
        buckets=len(buckets),
        records_kept=kept,
        records_removed=len(removed),
        removed_paths=tuple(removed),
    )

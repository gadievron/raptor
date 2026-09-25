"""Project + run-directory discovery shared by the operator CLIs.

``raptor-review`` and ``raptor-run-status`` both answer "which project
output dir governs this invocation?" and "which run dirs does it hold,
newest first?". One implementation here — per-CLI copies had already
drifted (one guarded a vanished run dir's ``stat``, the other did
not).
"""

from __future__ import annotations

from pathlib import Path

from core.json import load_json
from core.logging import get_logger

logger = get_logger()

# Registry / run-metadata records are small; the shared small-record
# budget the review CLI applies to the same files.
_MAX_META_BYTES = 8 * 1024 * 1024


def project_output_dir(name: str | None = None) -> Path | None:
    """The output directory of project ``name``, or of the active
    project when ``name`` is falsy. ``None`` when the project (or an
    active default) does not resolve to an existing directory —
    callers that received an EXPLICIT name must hard-error on None
    (project doctrine: never a silent fallback)."""
    from core.startup import PROJECTS_DIR, get_active_name

    if not name:
        try:
            name = get_active_name()
        except Exception:  # noqa: BLE001 — no active project is a normal state
            name = None
        if not name:
            return None
    data = load_json(PROJECTS_DIR / f"{name}.json",
                     max_bytes=_MAX_META_BYTES)
    if isinstance(data, dict) and data.get("output_dir"):
        candidate = Path(data["output_dir"])
        if candidate.is_dir():
            return candidate
    return None


def run_started_key(run_dir: Path) -> str:
    """Ordering key for newest-first run selection: the run's own
    recorded start timestamp (ISO-8601 UTC in ``.raptor-run.json``,
    lexicographically ordered), NOT directory mtime — a touched or
    restored old run dir must not win. Legacy/corrupt metadata falls
    back to mtime rendered in the same ISO shape so keys stay
    comparable; a run dir that VANISHES between enumeration and the
    sort (concurrent ``/project clean``) keys as oldest instead of
    raising out of the caller's listing."""
    meta = load_json(run_dir / ".raptor-run.json",
                     max_bytes=_MAX_META_BYTES)
    ts = meta.get("timestamp") if isinstance(meta, dict) else None
    if isinstance(ts, str) and ts:
        return ts
    from datetime import datetime, timezone
    try:
        mtime = run_dir.stat().st_mtime
    except OSError:
        mtime = 0.0
    return datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()


def run_dirs_newest_first(project_dir: Path) -> list[Path]:
    """Run directories of ``project_dir`` (children carrying a
    ``.raptor-run.json``), newest first."""
    try:
        candidates = [
            d for d in Path(project_dir).iterdir()
            if d.is_dir() and (d / ".raptor-run.json").is_file()
        ]
    except OSError:
        return []
    return sorted(candidates, key=run_started_key, reverse=True)


__all__ = [
    "project_output_dir",
    "run_dirs_newest_first",
    "run_started_key",
]

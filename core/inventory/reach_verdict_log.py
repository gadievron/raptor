"""Per-language reachability-verdict distribution log.

A telemetry sidecar that aggregates how many times each (language,
verdict) pair fires across all ``classify_reachability`` calls. The
chokepoint records every verdict it produces; counts accumulate
in-memory and flush to a JSON sidecar at process exit (or via explicit
:func:`flush`).

**Why it exists.** Reachability accuracy work (framework entry catalog,
ServiceLoader/setuptools parsers, JS/Java dead-island, CHA precision)
all need an empirical signal: "how often does verdict X fire on
language Y across real operator runs?" Without that signal we'd be
optimising blind. The reach_audit corpus measures verdict CORRECTNESS
on a labelled fixture; this log measures verdict FREQUENCY on whatever
the operator actually scans.

**Schema** (``out/reach_verdict_log.json`` by default)::

    {
      "version": 1,
      "languages": {
        "python": {
          "verdicts": {"reachable": 1023, "no_path_from_entry": 47, ...},
          "last_seen_at": "2026-06-01T14:23:00Z"
        },
        "c": {...},
        ...
      }
    }

**Privacy.** Records only ``(language, verdict_string)`` pairs — never
source code, finding details, function names, or file paths. Safe to
pool across projects (the cross-project signal is the point).

**Concurrency.** Writes go through ``_with_lock`` (``flock`` on the
sidecar), so multi-process raptor runs accumulate without losing
increments. Same pattern as ``llm_scorecard`` (q.v.).

**Cost.** Schema is bounded: ``num_languages × num_verdict_strings ≈
100 entries``. JSON stays tiny (a few KB after years of use).
"""

from __future__ import annotations

import atexit
import fcntl
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from core.json import load_json, save_json
from core.logging import get_logger

logger = get_logger()

SCHEMA_VERSION = 1

# In-memory accumulator, keyed by (language, verdict) → count. Module-
# level so every ``record_verdict`` call within the process aggregates;
# ``flush`` reads + clears this buffer in one shot under the lock.
_IN_MEMORY: Dict[str, Dict[str, int]] = {}
_LOCK = threading.Lock()


def _sidecar_path() -> Path:
    """Resolve the sidecar JSON location.

    Honours ``RAPTOR_REACH_VERDICT_LOG`` env var if set (tests use this
    to redirect into a tmp dir). Otherwise lands under the RAPTOR repo's
    ``out/`` directory — the same shape as ``llm_scorecard.json``.
    """
    override = os.environ.get("RAPTOR_REACH_VERDICT_LOG")
    if override:
        return Path(override)
    raptor_dir = os.environ.get("RAPTOR_DIR")
    if raptor_dir:
        return Path(raptor_dir) / "out" / "reach_verdict_log.json"
    # Fall back to cwd-relative — defensive; the launcher always sets
    # RAPTOR_DIR, but tests that don't go through the launcher hit this
    # branch.
    return Path("out") / "reach_verdict_log.json"


def record_verdict(language: Optional[str], verdict: Optional[str]) -> None:
    """Increment the in-memory counter for ``(language, verdict)``.

    Both arguments may be ``None`` — typically ``language`` is unknown
    when the inventory has no file record for the target's path; the
    call becomes a no-op rather than failing the chokepoint. Same for
    a verdict that's somehow empty.

    Threadsafe: a process-wide :class:`threading.Lock` guards the
    in-memory dict so concurrent calls from a ``ThreadPoolExecutor``
    don't race. Cross-process safety is provided by :func:`flush`'s
    flock at write time.
    """
    if not language or not verdict:
        return
    # ``RAPTOR_REACH_VERDICT_LOG_DISABLED`` is the operator opt-out (and
    # the test-suite default via conftest). Checking it per-call keeps
    # the in-memory dict empty so a long-running disabled process never
    # carries stale counters, AND lets a test fixture toggle telemetry
    # mid-process by tweaking the env. Cheap: env-var lookup is a hash
    # probe, fires before the lock.
    if os.environ.get("RAPTOR_REACH_VERDICT_LOG_DISABLED"):
        return
    with _LOCK:
        per_lang = _IN_MEMORY.setdefault(language, {})
        per_lang[verdict] = per_lang.get(verdict, 0) + 1


def _drain_in_memory() -> Dict[str, Dict[str, int]]:
    """Atomically swap the in-memory accumulator for an empty dict and
    return the prior contents. Holding ``_LOCK`` for the swap ensures no
    increment is lost between the read and the reset.
    """
    with _LOCK:
        # Snapshot then clear-in-place. Can't reassign module-level
        # from inside a function without ``global``; clear-in-place
        # preserves the reference for any concurrent recorder.
        out = {lang: dict(v) for lang, v in _IN_MEMORY.items()}
        _IN_MEMORY.clear()
        return out


def _merge_disk(path: Path, increments: Dict[str, Dict[str, int]]) -> None:
    """Read-modify-write the sidecar under flock.

    Schema-version-strict: refuses to write back data of an unrecognised
    schema — better to surface than silently downgrade.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    # ``a+`` semantics — create if absent, never written to. flock
    # operates on the inode so the lock-file's contents are irrelevant.
    with open(lock_path, "a+") as lock_fh:
        fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
        try:
            if path.exists():
                try:
                    data = load_json(path)
                except Exception as e:
                    logger.warning(
                        "reach_verdict_log: corrupt JSON at %s — "
                        "reading as empty (%s)", path, e)
                    data = None
            else:
                data = None
            if data is None:
                data = {"version": SCHEMA_VERSION, "languages": {}}
            version = data.get("version")
            if version != SCHEMA_VERSION:
                raise RuntimeError(
                    f"reach_verdict_log: refusing to write — sidecar at "
                    f"{path} has version={version!r}, expected "
                    f"{SCHEMA_VERSION!r}. Delete the sidecar to reset."
                )
            languages: Dict[str, Any] = data.setdefault("languages", {})
            now = datetime.now(timezone.utc).isoformat(timespec="seconds")
            for lang, verdicts in increments.items():
                slot = languages.setdefault(
                    lang, {"verdicts": {}, "last_seen_at": now})
                vs = slot.setdefault("verdicts", {})
                for v, n in verdicts.items():
                    vs[v] = int(vs.get(v, 0)) + int(n)
                slot["last_seen_at"] = now
            save_json(path, data)
        finally:
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)


def _redeposit(increments: Dict[str, Dict[str, int]]) -> None:
    """Merge ``increments`` back into the in-memory accumulator. Used
    when a flush attempt fails — the drained counts MUST NOT be lost,
    so we put them back where they were and let the next flush try
    again (or the operator notice via the warning log and recover)."""
    if not increments:
        return
    with _LOCK:
        for lang, verdicts in increments.items():
            per_lang = _IN_MEMORY.setdefault(lang, {})
            for v, n in verdicts.items():
                per_lang[v] = per_lang.get(v, 0) + int(n)


def flush(path: Optional[Path] = None) -> None:
    """Drain the in-memory accumulator and merge into the sidecar.

    ``path`` defaults to :func:`_sidecar_path`. Tests pass an explicit
    path. Safe to call repeatedly — drains each time, no-ops if empty.
    Safe to call from atexit; suppresses every exception (telemetry
    must never block process exit).

    Failure mode: if the disk merge raises (corrupt sidecar that even
    the fallback can't read, schema-version refusal, EIO, …), the
    drained increments are **re-deposited** into the in-memory
    accumulator. Without this, a schema-version mismatch would silently
    discard every recorded verdict for the rest of the process lifetime
    — one of those bugs that looks fine in tests and bleeds data in
    production.
    """
    increments = _drain_in_memory()
    if not increments:
        return
    try:
        _merge_disk(path or _sidecar_path(), increments)
    except Exception as e:
        logger.warning("reach_verdict_log: flush failed, "
                       "preserving increments in memory (%s)", e)
        _redeposit(increments)


def summarize(path: Optional[Path] = None) -> Dict[str, Dict[str, int]]:
    """Return the on-disk verdict distribution as
    ``{language: {verdict: count}}``. Empty dict if the sidecar doesn't
    exist or is unreadable. For CLI inspection — does not flush.
    """
    p = path or _sidecar_path()
    if not p.exists():
        return {}
    try:
        data = load_json(p)
    except Exception as e:
        logger.warning("reach_verdict_log: read failed (%s)", e)
        return {}
    if not isinstance(data, dict):
        return {}
    languages = data.get("languages") or {}
    return {
        lang: dict(slot.get("verdicts") or {})
        for lang, slot in languages.items()
        if isinstance(slot, dict)
    }


def reset(path: Optional[Path] = None) -> None:
    """Clear in-memory counter AND delete the sidecar. Used by tests
    and the operator-facing ``--reset`` CLI flag."""
    with _LOCK:
        _IN_MEMORY.clear()
    p = path or _sidecar_path()
    if p.exists():
        p.unlink()
    lock_path = p.with_suffix(p.suffix + ".lock")
    if lock_path.exists():
        lock_path.unlink()


def _clear_after_fork_in_child() -> None:
    """Reset the in-memory accumulator in a forked child.

    Without this, a ``multiprocessing.Process`` / ``os.fork`` child
    inherits the parent's accumulator AND atexit registration: at
    child exit it flushes the inherited counts (already attributable
    to the parent's eventual flush), so the same increments are written
    twice. Clearing in-place at the after-fork-in-child hook is the
    standard pattern for "this state belongs to a single process,
    not a process tree."

    The atexit-registered ``flush`` still fires in the child, but it
    drains an empty accumulator → no-op write → no double-count.
    """
    with _LOCK:
        _IN_MEMORY.clear()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_clear_after_fork_in_child)


# atexit registration — opt-out via ``RAPTOR_REACH_VERDICT_LOG_DISABLED``
# (test suites that don't want their stray verdicts to land in the real
# sidecar should set this OR redirect with ``RAPTOR_REACH_VERDICT_LOG``).
if not os.environ.get("RAPTOR_REACH_VERDICT_LOG_DISABLED"):
    atexit.register(flush)

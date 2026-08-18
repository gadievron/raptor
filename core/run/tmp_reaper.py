"""Reap stale RAPTOR temp artifacts orphaned by killed runs.

Several long-lived runtime components park small artifacts in the system
temp dir and clean them up on exit:

  - ``raptor-llm-<run_id>-*/``  — LLM dispatcher socket dir
    (:mod:`core.llm.dispatcher.server`; ``shutdown()`` + ``atexit``)
  - ``raptor-cc-cwd-*/``        — neutral cwd for ``claude -p`` dispatch
    (:mod:`core.llm.cc_adapter`; ``atexit``)
  - ``raptor-joern-ws-*/``      — disposable Joern server workspace
    (:mod:`packages.joern.server`; removed on ``stop()``)
  - ``raptor-calibrate-*/``     — sandbox calibration scratch
    (:mod:`core.sandbox.calibrate`; ``TemporaryDirectory``)
  - ``raptor_auto_*/``          — automated-scan clone scratch
    (``packages/static-analysis/scanner.py``; rmtree in ``finally``)
  - ``raptor_git_*/``           — agentic git clone scratch
    (``raptor_agentic.py``; rmtree + its own stale sweep)
  - ``raptor_decomp_*/``        — r2 decompilation scratch
    (:mod:`core.audit.orchestrator`; rmtree in ``finally``)
  - ``audit_sweep_*.yaml``      — per-hypothesis Semgrep rule files
    (:mod:`core.audit.hypothesis_mapping`; unlinked in the sweep's
    ``finally``)
  - ``raptor-audit-cfg-*.json`` — sandbox audit-config tempfiles
    (:mod:`core.sandbox._spawn`; unlinked in lifecycle + own sweep)
  - ``raptor-cocci-tmp-*/`` and ``raptor-cocci-*.cocci`` — spatch
    scratch dir and harnessed rule files
    (``packages/coccinelle/runner.py``; cleaned in its finally)
  - ``cocci-output-*`` / ``cocci_small_output-*`` — spatch's own
    per-file working copies, stranded when spatch is killed
  - ``wrapped-script*.sc``      — written by the Joern JVM launcher
    itself next to our workspace dirs

All of those cleanups are exit-path-only: SIGKILL, OOM, and unhandled
SIGTERM (Python does not run ``atexit`` hooks on SIGTERM) skip them, so
every hard-killed run leaks its set. This module sweeps such orphans at
the start of the next run.

``raptor-observe-*`` dirs are deliberately NOT reaped: the observe CLI
only leaves one behind when the operator passed ``--keep`` (or ``--out``)
to preserve it for re-inspection.

Safety posture (world-writable /tmp on a shared box):

  - Only entries directly under :func:`tempfile.gettempdir` whose name
    matches a known RAPTOR prefix are considered.
  - ``lstat`` only — a symlink planted at a matching name is never
    followed, and anything not owned by the current euid is skipped.
  - Entries younger than the age floor are skipped, so a concurrent
    run's live artifacts survive even if the liveness probes miss.
  - Dirs that any live process uses as its cwd, or that contain a unix
    socket something still answers on, are skipped regardless of age.
  - Removal is best-effort; errors never propagate to the caller.

Set ``RAPTOR_TMP_REAP_MAX_AGE_H=0`` to disable the sweep, or to another
number of hours to move the age floor (default 24).
"""

from __future__ import annotations

import errno
import logging
import os
import shutil
import socket
import stat
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

# Dir prefixes whose creators ALWAYS intend cleanup — presence past the
# age floor means the owning process died without its exit path.
_DIR_PREFIXES = (
    "raptor-llm-",
    "raptor-cc-cwd-",
    "raptor-joern-ws-",
    "raptor-calibrate-",
    "raptor_auto_",
    "raptor_git_",
    "raptor_decomp_",
    # Per-invocation spatch scratch (packages/coccinelle/runner.py);
    # rmtree'd in the runner's finally, so survival past the floor
    # means the whole RAPTOR process died mid-sweep.
    "raptor-cocci-tmp-",
    # Barrier-synthesis scratch (core/dataflow/barrier_synth.py);
    # rmtree'd in the CLI's finally when auto-created.
    "trust-synth-work-",
    # IRIS per-refinement CodeQL pack scratch (core/iris/codeql_runner.py);
    # rmtree'd in the runner's finally.
    "raptor-iris-codeql-",
    # Recon-agent clone scratch (packages/recon/agent.py); rmtree'd on
    # exit unless --keep. A --keep dir surviving past the age floor is
    # forgotten debug output — the sweep reclaims it like any other.
    "raptor_recon_",
    # CPython multiprocessing's own resource dir — leaks when a process
    # (e.g. a sandboxed child we SIGKILL) dies without cleanup.
    "pymp-",
)

# Prefixes registered at runtime by core.run.scratch.scratch_dir for
# system-tmp scratch areas. Per-process: a registration made here is
# visible to every later sweep in the SAME process (a long-lived
# orchestrator reaping strays from an earlier crashed run), but not to
# unrelated processes — cross-process reaping still requires a static
# _DIR_PREFIXES entry above.
_RUNTIME_DIR_PREFIXES: set[str] = set()


def register_dir_prefix(prefix: str) -> None:
    """Register *prefix* for the stale-tmp dir sweep (this process)."""
    if prefix:
        _RUNTIME_DIR_PREFIXES.add(prefix)


def _dir_prefixes() -> tuple[str, ...]:
    return _DIR_PREFIXES + tuple(_RUNTIME_DIR_PREFIXES)


# File patterns with the same always-cleaned contract.
_FILE_PATTERNS = (
    ("audit_sweep_", ".yaml"),
    ("raptor-audit-cfg-", ".json"),
    ("raptor-cocci-", ".cocci"),
    ("wrapped-script", ".sc"),
    # spatch's own per-file working copies. Normally confined to the
    # private scratch dir above; these top-level patterns catch strays
    # from spatch invocations that predate the scoped TMPDIR (or any
    # tool invoking spatch without one). Empty suffix = prefix match.
    ("cocci-output-", ""),
    ("cocci_small_output-", ""),
)

_MAX_AGE_ENV = "RAPTOR_TMP_REAP_MAX_AGE_H"
_DEFAULT_MAX_AGE_H = 24.0

# Per-process JSONL audit logs under RaptorConfig.LOG_DIR. One file per
# process and no rotation, so test suites alone mint hundreds per day.
# OPT-IN, unlike the tmp sweep: logs are audit data with forensic value,
# and deleting audit data must be an operator decision, not a default.
_LOG_MAX_AGE_ENV = "RAPTOR_LOG_REAP_MAX_AGE_D"

# Failed/cancelled run dirs (reap_stale_runs). Completed runs are
# results and are never age-reaped.
_RUN_MAX_AGE_ENV = "RAPTOR_RUN_REAP_MAX_AGE_D"
_DEFAULT_RUN_AGE_D = 30.0

# Mirrors core.run.metadata.RUN_METADATA_FILE — literal here to keep
# this module import-light (metadata imports US at start_run time).
_RUN_METADATA_FILE = ".raptor-run.json"


def _max_age_seconds() -> float | None:
    """Age floor in seconds, or None when the sweep is disabled."""
    raw = os.environ.get(_MAX_AGE_ENV, "")
    if raw:
        try:
            hours = float(raw)
        except ValueError:
            logger.debug("ignoring non-numeric %s=%r", _MAX_AGE_ENV, raw)
            hours = _DEFAULT_MAX_AGE_H
    else:
        hours = _DEFAULT_MAX_AGE_H
    if hours <= 0:
        return None
    return hours * 3600.0


def _live_cwds() -> set[str]:
    """Working directories of every process this user can inspect."""
    cwds: set[str] = set()
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        return cwds
    for pid in pids:
        try:
            cwds.add(os.readlink(f"/proc/{pid}/cwd"))
        except OSError:
            continue
    return cwds


def _socket_answers(sock_path: Path) -> bool:
    """True when something still accepts connections on *sock_path*."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.settimeout(0.2)
        s.connect(str(sock_path))
        return True
    except OSError as exc:
        # ECONNREFUSED / ENOENT → dead socket. EACCES or anything else
        # ambiguous → assume live, err on the side of not reaping.
        return exc.errno not in (errno.ECONNREFUSED, errno.ENOENT)
    finally:
        s.close()


def _dir_in_use(path: Path, live_cwds: set[str]) -> bool:
    """Liveness probes for a candidate dir: cwd references, live sockets."""
    p = str(path)
    if any(cwd == p or cwd.startswith(p + os.sep) for cwd in live_cwds):
        return True
    try:
        entries = list(path.iterdir())
    except OSError:
        return True
    for entry in entries:
        try:
            mode = entry.lstat().st_mode
        except OSError:
            return True
        if stat.S_ISSOCK(mode) and _socket_answers(entry):
            return True
    return False


def reap_stale_tmp(now: float | None = None) -> list[Path]:
    """Remove orphaned RAPTOR temp artifacts; return the reaped paths.

    Best-effort by contract: any per-entry error skips that entry, any
    unexpected error aborts silently with a debug log. Never raises.
    """
    try:
        return _reap(now)
    except Exception as exc:  # noqa: BLE001 — sweep must never block a run
        logger.debug("stale-tmp sweep aborted: %s", exc)
        return []


def _reap(now: float | None) -> list[Path]:
    max_age = _max_age_seconds()
    if max_age is None:
        return []
    tmp_root = Path(tempfile.gettempdir())
    try:
        names = os.listdir(tmp_root)
    except OSError:
        return []

    dir_candidates: list[Path] = []
    file_candidates: list[Path] = []
    for name in names:
        if any(name.startswith(p) for p in _dir_prefixes()):
            dir_candidates.append(tmp_root / name)
        elif any(
            name.startswith(pre) and name.endswith(suf)
            for pre, suf in _FILE_PATTERNS
        ):
            file_candidates.append(tmp_root / name)
    if not dir_candidates and not file_candidates:
        return []

    if now is None:
        import time

        now = time.time()
    euid = os.geteuid()
    reaped: list[Path] = []

    # /proc scan only when a dir is actually up for consideration.
    live_cwds: set[str] | None = None

    for path in dir_candidates:
        try:
            st = path.lstat()
        except OSError:
            continue
        if not stat.S_ISDIR(st.st_mode):
            continue  # symlink or file squatting on our prefix — not ours
        if st.st_uid != euid:
            continue
        if now - st.st_mtime < max_age:
            continue
        if live_cwds is None:
            live_cwds = _live_cwds()
        if _dir_in_use(path, live_cwds):
            continue
        shutil.rmtree(path, ignore_errors=True)
        if not path.exists():
            reaped.append(path)

    for path in file_candidates:
        try:
            st = path.lstat()
        except OSError:
            continue
        if not stat.S_ISREG(st.st_mode):
            continue
        if st.st_uid != euid:
            continue
        if now - st.st_mtime < max_age:
            continue
        try:
            path.unlink()
        except OSError:
            continue
        reaped.append(path)

    if reaped:
        logger.info(
            "reaped %d stale temp artifact(s) from earlier interrupted runs",
            len(reaped),
        )
    return reaped


def reap_stale_runs(parent: Path, now: float | None = None) -> list[Path]:
    """Remove aged-out failed/cancelled run dirs under *parent*.

    Nothing else deletes flat run dirs: ``_cleanup_abandoned`` only
    relabels status, and ``/project clean`` is manual and
    project-scoped. Failed runs are usually a few KB of metadata, but
    interrupted agentic runs can strand tens of MB (a 37M checklist was
    observed in one), and either way they pile up forever.

    Deliberately narrow:

      - Only dirs carrying a ``.raptor-run.json`` whose status is
        ``failed`` or ``cancelled``. Completed runs are RESULTS — never
        auto-deleted. Running runs belong to the liveness machinery
        (`_cleanup_abandoned`, the lifecycle hook), not to age sweeps.
      - Only past the age floor: ``RAPTOR_RUN_REAP_MAX_AGE_D`` (default
        30 days, 0 disables), judged by the run's own start timestamp
        with dir mtime as fallback.
      - lstat-only + current-euid ownership, same posture as the tmp
        sweep; non-run dirs (logs/, llm_cache/, projects/) carry no run
        metadata and are never touched.

    Best-effort by contract — never raises.
    """
    try:
        return _reap_runs(parent, now)
    except Exception as exc:  # noqa: BLE001 — sweep must never block a run
        logger.debug("stale-run sweep aborted: %s", exc)
        return []


def _reap_runs(parent: Path, now: float | None) -> list[Path]:
    raw = os.environ.get(_RUN_MAX_AGE_ENV, "")
    if raw:
        try:
            days = float(raw)
        except ValueError:
            logger.debug("ignoring non-numeric %s=%r", _RUN_MAX_AGE_ENV, raw)
            days = _DEFAULT_RUN_AGE_D
    else:
        days = _DEFAULT_RUN_AGE_D
    if days <= 0:
        return []
    max_age = days * 86400.0

    parent = Path(parent)
    try:
        children = list(parent.iterdir())
    except OSError:
        return []
    if now is None:
        import time

        now = time.time()
    euid = os.geteuid()
    reaped: list[Path] = []
    for d in children:
        try:
            st = d.lstat()
        except OSError:
            continue
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != euid:
            continue
        if d.name.startswith((".", "_")):
            continue
        meta_path = d / _RUN_METADATA_FILE
        try:
            import json

            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(meta, dict):
            continue
        if meta.get("status") not in ("failed", "cancelled"):
            continue
        age = _run_age_seconds(meta, st, now)
        if age < max_age:
            continue
        shutil.rmtree(d, ignore_errors=True)
        if not d.exists():
            reaped.append(d)
    if reaped:
        logger.info(
            "reaped %d failed/cancelled run dir(s) older than %g days "
            "under %s", len(reaped), days, parent,
        )
    return reaped


def _run_age_seconds(meta: dict, st: os.stat_result, now: float) -> float:
    """Age from the run's own start timestamp; dir mtime as fallback."""
    ts = meta.get("timestamp")
    if isinstance(ts, str):
        from datetime import datetime, timezone

        try:
            started = datetime.fromisoformat(ts)
            if started.tzinfo is None:
                started = started.replace(tzinfo=timezone.utc)
            return now - started.timestamp()
        except ValueError:
            pass
    return now - st.st_mtime


def reap_stale_logs(now: float | None = None) -> list[Path]:
    """Remove per-process audit logs older than the operator's age floor.

    ``core.logging`` writes one ``raptor_<epoch>_pid<pid>_<ns>.jsonl``
    per process into ``RaptorConfig.LOG_DIR`` with no rotation, so the
    dir accumulates a file for every raptor process ever started. A
    live process keeps its file's mtime fresh, so an age gate alone is
    a safe liveness proxy here.

    DISABLED unless the operator opts in: these files are the audit
    trail, and audit data is only deleted on explicit instruction —
    set ``RAPTOR_LOG_REAP_MAX_AGE_D=<days>`` (e.g. 14) to enable.
    Best-effort by contract — never raises.
    """
    try:
        return _reap_logs(now)
    except Exception as exc:  # noqa: BLE001 — sweep must never block a run
        logger.debug("stale-log sweep aborted: %s", exc)
        return []


def _reap_logs(now: float | None) -> list[Path]:
    raw = os.environ.get(_LOG_MAX_AGE_ENV, "")
    if not raw:
        return []  # opt-in only — never delete audit data by default
    try:
        days = float(raw)
    except ValueError:
        logger.debug("ignoring non-numeric %s=%r", _LOG_MAX_AGE_ENV, raw)
        return []
    if days <= 0:
        return []
    max_age = days * 86400.0

    from core.config import RaptorConfig

    log_dir = Path(RaptorConfig.LOG_DIR)
    if not log_dir.is_dir():
        return []
    if now is None:
        import time

        now = time.time()
    euid = os.geteuid()
    reaped: list[Path] = []
    for path in log_dir.glob("raptor_*.jsonl"):
        try:
            st = path.lstat()
        except OSError:
            continue
        if not stat.S_ISREG(st.st_mode) or st.st_uid != euid:
            continue
        if now - st.st_mtime < max_age:
            continue
        try:
            path.unlink()
        except OSError:
            continue
        reaped.append(path)
    if reaped:
        logger.info("reaped %d audit log file(s) older than %g days",
                    len(reaped), days)
    return reaped

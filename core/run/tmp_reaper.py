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
    matches a known RAPTOR prefix, an anchored third-party tool name
    that only RAPTOR's own tool runs strand here
    (``_ANCHORED_DIR_PREFIXES``), or a neutral de-branded scratch name
    anchored to its exact mkdtemp suffix
    (``_MKDTEMP_ANCHORED_DIR_PREFIXES``) are considered.
  - ``lstat`` only — a symlink planted at a matching name is never
    followed, and anything not owned by the current euid is skipped.
  - Entries younger than the age floor are skipped, so a concurrent
    run's live artifacts survive even if the liveness probes miss.
  - Dirs that any live process uses as its cwd, or that contain a unix
    socket something still answers on, are skipped regardless of age.
  - Removal is best-effort; errors never propagate to the caller.

Set ``RAPTOR_TMP_REAP_MAX_AGE_H=0`` to disable the sweep, or to another
number of hours to move the age floor (default 24; floors below two
scratch-keepalive ticks clamp to 30 min — see ``_max_age_seconds``).
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
    # Joern CPG build scratch (packages/joern/runner.py mkdtemp);
    # rmtree'd on the runner's exit path, so hard-killed Joern builds
    # leak one per invocation — observed accumulating by the hundreds.
    "raptor-joern-cpg-",
    # cve-diff working dirs (packages/cve_diff cli TemporaryDirectory
    # and the bench harness's cve-diff-bench- mkdtemp — both match
    # this prefix); cleaned on exit, leaked on SIGKILL/OOM.
    "cve-diff-",
    # Ghidra working copies: session/headless scratch (rmtree'd in
    # their finally blocks) and the persistent server's work dir
    # (removed on stop(); survives when the parent dies or a worker
    # hangs past the join grace).
    "raptor-ghidra-",
    # Per-session pytest temp containment (root conftest.py): the test
    # session points TMPDIR/tempfile.tempdir at one scratch dir so raw
    # tempfile call sites in tests and code under test land inside it.
    # Removed on normal session exit; a killed test session leaks one
    # dir per pytest process (one per xdist worker), reclaimed here by
    # any later process's sweep.
    "raptor-pytest-",
    # Coordinator-isolation probe output dirs (core/sandbox/tests/
    # test_coordinator_isolation.py): removed via atexit, but the first
    # ones are minted at collection time — before the conftest TMPDIR
    # containment exists — so a killed collection/run leaks them
    # directly under the system tmp (one per collecting worker).
    "raptor-coord-isolation-",
    # r2 analysis scratch (packages/binary_analysis/
    # radare2_understand.py, via core.run.scratch); removed when the
    # analysis exits.
    "r2-sandbox-",
    # Cocci-hunt sandbox scratch (packages/code_understanding/dispatch/
    # hunt_cocci_dispatch.py, via core.run.scratch); removed when the
    # dispatch exits.
    "raptor-cocci-hunt-",
    # Binary-oracle env-build artifact dir (core/analysis/
    # binary_oracle_cli.py); the artifacts outlive the resolve call and
    # are rmtree'd atexit, which SIGKILL skips.
    "raptor-oracle-envbuild-",
    # Corpus excerpt trees (core/audit/corpus/run_corpus.py); ownership
    # passes to the corpus loop, released in its finally. The owner
    # holds a scratch keepalive while live (excerpt trees are written
    # once, then read for multi-day runs — quiet mtime is normal), so
    # presence past the floor always means a dead owner.
    "corpus-excerpt-",
    # Compose staging copies (core/container/compose.py); ownership
    # passes to the caller, cleanup_staging() after down_stack. The
    # owner holds a scratch keepalive while the stack runs (bind-mount
    # sources don't refresh the top-level mtime).
    "raptor-compose-",
    # Env-provisioner work dirs (core/env/provision.py; removed at
    # Environment.teardown / provision failure). The owner holds a
    # scratch keepalive while the environment is live (a sandbox
    # rootfs's mtime froze at export). The startswith match also
    # covers core/env/build.py's raptor-env-build- staging contexts —
    # same always-cleaned contract, context-manager lifetime.
    "raptor-env-",
    # cve-env source-checkout work dirs (packages/cve_env
    # tools/source_build.py; cleanup()-scoped). retain() hands
    # ownership to the operator — a retained dir surviving past the
    # age floor is forgotten debug output, reclaimed like
    # raptor_recon_ above.
    "cve-env-source-",
    # cve-env fused-build docker contexts (packages/cve_env
    # agent/tools.py; rmtree'd on build failure, kept for the agent
    # session on success — kept contexts have no exit-path cleanup at
    # all and are reclaimed only by this sweep past the age floor).
    "cve-env-dfgbuild-",
    # Joern compat-matrix scratch (packages/joern/scripts/
    # compat_matrix.py): per-version fixture/CPG dirs (via
    # core.run.scratch) and the auto-created download workdir
    # (rmtree'd unless --keep; --keep survivors past the floor are
    # forgotten debug output, same contract as raptor_recon_).
    "joern-matrix-",
    # SCA stress-run ephemeral clone root (packages/sca/calibration/
    # stress.py, RAPTOR_SCA_STRESS_EPHEMERAL=1 mode; rmtree'd in its
    # finally).
    "raptor-sca-stress-",
    # Egress-proxy lane socket dirs (core/sandbox/proxy.py
    # make_lane_dir; caller-owned rmtree with atexit + SIGTERM hooks,
    # so only SIGKILL strands one). A live lane's socket still answers
    # and the in-use probe below keeps it out of the sweep. Lanes
    # minted under make_lane_dir's short-path fallback bases
    # (/run/user/<uid>, /tmp when the temp dir is deep) sit outside
    # the gettempdir() root this sweep covers — kept, never
    # mis-deleted.
    ".raptor-lane-",
    # Sandbox root stubs (core/sandbox/_spawn mkdtemp and the mount-ns
    # pid-named fallback); removed post-exit by _cleanup_stub, leaked
    # when the orchestrator itself is killed first. A child that
    # legitimately outlives the age floor (a multi-day fuzz campaign)
    # is NOT protected by the probes — a pivoted child's host-visible
    # cwd is "/", not the stub — and its stub WILL be reaped. That is
    # benign by construction, not by the floor: host-side the stub is
    # an empty dentry (the mount tree lives in the child's namespace,
    # which keeps its own references; rmtree lazy-detaches without
    # disturbing the child), and _cleanup_stub tolerates the dir
    # already being gone.
    ".raptor-sbx-",
    # Landlock-only restricted-posture private scratch
    # (core/sandbox/context.py); rmtree'd at context teardown. A live
    # context holds a keepalive registration (core.run.scratch) for
    # exactly the reaper's sake: a sandboxed campaign can sit
    # mtime-quiet past the floor while its TMPDIR still points here.
    # Legacy branded name — fresh mints use the neutral .scr- prefix
    # in _MKDTEMP_ANCHORED_DIR_PREFIXES below.
    ".raptor-scratch-",
    # Persona home tmpdirs (core/sandbox/context.py); rmtree'd at
    # context teardown. Legacy branded name — fresh mints use the
    # neutral .fp- prefix below.
    "raptor-persona-",
    # Test scratch from core/sandbox/tests/test_spawn_lifecycle_
    # hardening.py (addCleanup'd there now, but strays from
    # non-contained historical runs persist) — same test-only
    # contract as raptor-coord-isolation- above.
    "raptor-pdsig-",
    "raptor-hifd-",
)

# Third-party scratch names carry no RAPTOR marker and end in a bare
# word, so a plain prefix match would also claim an operator's own
# same-named files (a scala-repl-pp source checkout, a
# semmleTempDir.bak someone parked). These match only when the
# remainder after the prefix is exactly the creating tool's random
# decimal/hex suffix.
_ANCHORED_DIR_PREFIXES = (
    # CodeQL CLI's own scratch dirs, stranded when a codeql child is
    # killed — same third-party contract as spatch's cocci-output-
    # entries in _FILE_PATTERNS.
    "semmleTempDir",
    "codeql-packaging",
    # Joern's script-wrapping scratch (a nested JVM ignores the
    # launcher's java.io.tmpdir argv flag), stranded by every
    # timeout-killed `joern --script` query — the dir sibling of the
    # wrapped-script*.sc entry in _FILE_PATTERNS.
    "scala-repl-pp",
)

# Neutral child-visible scratch names, de-branded so the target
# cannot fingerprint the framework from its TMPDIR: the Landlock-only
# private scratch (.scr-) and the persona home (.fp-), both minted by
# core/sandbox/context.py, rmtree'd at context teardown, and
# keepalive-registered while their context lives. Too short to claim
# on prefix alone — an operator's ".scr-notes" must survive — so
# these match only when the remainder is exactly a tempfile random
# suffix.
_MKDTEMP_ANCHORED_DIR_PREFIXES = (
    ".scr-",
    ".fp-",
)

# tempfile's random names draw eight characters from
# lowercase+digits+underscore.
_MKDTEMP_SUFFIX_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyz0123456789_")
_MKDTEMP_SUFFIX_LEN = 8


def _mkdtemp_anchored_match(name: str, prefix: str) -> bool:
    """True when *name* is *prefix* + one exact tempfile random suffix."""
    rest = name[len(prefix):]
    return (name.startswith(prefix)
            and len(rest) == _MKDTEMP_SUFFIX_LEN
            and all(c in _MKDTEMP_SUFFIX_CHARS for c in rest))


_TOOL_RANDOM_CHARS = frozenset("0123456789abcdef")


def _anchored_name_match(name: str, prefix: str, suffix: str = "") -> bool:
    """True when *name* is *prefix* + tool-random hex/decimal + *suffix*.

    The middle must be at least 4 characters: every creating tool
    appends a long random number, and the floor keeps short
    operator-made names (a "scala-repl-pp2" copy) out of reach.
    """
    if not (name.startswith(prefix) and name.endswith(suffix)):
        return False
    middle = (name[len(prefix):len(name) - len(suffix)] if suffix
              else name[len(prefix):])
    return (len(middle) >= 4
            and all(c in _TOOL_RANDOM_CHARS for c in middle))

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

# Same anchored contract as _ANCHORED_DIR_PREFIXES, for files:
# joern-parse's frontend output-capture tempfiles (x2cpg<random>stdout
# / stderr), stranded when the parse driver is killed mid-frontend.
# RAPTOR's own parses now confine the driver's tmpdir to the build
# output dir, so these catch strays predating that and non-RAPTOR
# joern invocations.
_ANCHORED_FILE_PATTERNS = (
    ("x2cpg", "stdout"),
    ("x2cpg", "stderr"),
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

# Real run metadata is a few hundred bytes; 1 MiB is generous
# headroom while keeping a planted oversize file unread.
_RUN_METADATA_MAX_BYTES = 1 << 20


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
    floor_s = hours * 3600.0
    # A floor below two keepalive ticks could reap a LIVE registered
    # scratch dir between refreshes (core.run.scratch keeps owned
    # dirs at most one interval stale). Clamp loudly rather than
    # honour a data-loss window.
    from core.run.scratch import _KEEPALIVE_INTERVAL_S
    min_floor = 2 * _KEEPALIVE_INTERVAL_S
    if floor_s < min_floor:
        logger.warning(
            "%s=%g sets a %ds age floor below the scratch-keepalive "
            "safety minimum; clamping to %ds",
            _MAX_AGE_ENV, hours, int(floor_s), int(min_floor),
        )
        return min_floor
    return floor_s


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


# Bounded deep-scan budget for the internal-activity probe. Hitting the
# cap reads as "in use" — an unjudgeable dir is kept, and since the cap
# fires on every sweep, a dead dir with more entries than the budget is
# NEVER reaped by this sweep (deliberate fail-toward-keeping: giant
# strays are the operator's call, not an automated sweep's).
_DEEP_SCAN_MAX_ENTRIES = 4096


def _recent_activity(path: Path, now: float, max_age: float) -> bool:
    """Any entry beneath *path* modified within the age floor?

    The top-level mtime freezes at creation for most covered dirs (a
    git clone scratch, a joern workspace): a live run older than the
    floor whose tools still write INSIDE the dir must not be reaped on
    the top-level timestamp alone (keepalive-registered dirs refresh
    the top level; unregistered ones only show internal activity).
    Bounded walk — no symlink follow, lstat-only, early exit on the
    first fresh entry, hard entry cap — so a planted deep tree cannot
    turn the sweep into a filesystem crawl. Walk errors and the cap
    both read as activity (fail toward keeping, matching the sweep's
    never-delete-live posture); a dir over the cap is therefore kept
    on EVERY sweep, permanently exempt from this reaper.
    """
    seen = 0
    try:
        for root, dirs, files in os.walk(path, followlinks=False):
            for name in dirs + files:
                seen += 1
                if seen > _DEEP_SCAN_MAX_ENTRIES:
                    return True
                try:
                    st = os.lstat(os.path.join(root, name))
                except OSError:
                    continue
                if now - st.st_mtime < max_age:
                    return True
    except OSError:
        return True
    return False


def _dir_in_use(path: Path, live_cwds: set[str]) -> bool:
    """Liveness probes for a candidate dir: cwd references, live sockets.

    The socket scan covers TOP-LEVEL entries only. Every covered
    prefix keeps its socket at the top of its dir (lane.sock,
    llm.sock); a future prefix that nests its socket needs this
    walk deepened or it will be reaped while live.
    """
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
        if any(name.startswith(p) for p in _dir_prefixes()) or any(
            _anchored_name_match(name, p) for p in _ANCHORED_DIR_PREFIXES
        ) or any(
            _mkdtemp_anchored_match(name, p)
            for p in _MKDTEMP_ANCHORED_DIR_PREFIXES
        ):
            dir_candidates.append(tmp_root / name)
        elif any(
            name.startswith(pre) and name.endswith(suf)
            for pre, suf in _FILE_PATTERNS
        ) or any(
            _anchored_name_match(name, pre, suf)
            for pre, suf in _ANCHORED_FILE_PATTERNS
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
        # Internal-activity probe: the top-level mtime freezes at
        # creation for most covered dirs, so a >floor LIVE campaign
        # writing inside its scratch would otherwise be reaped mid-run.
        if _recent_activity(path, now, max_age):
            continue
        if live_cwds is None:
            live_cwds = _live_cwds()
        if _dir_in_use(path, live_cwds):
            continue
        # Same validation-to-delete identity pin as reap_stale_runs:
        # a same-uid writer swapping a different entry (or a symlink —
        # S_ISDIR on lstat is then false) into this name between the
        # checks above and the rmtree is skipped this sweep.
        try:
            st2 = path.lstat()
        except OSError:
            continue
        if (
            (st2.st_dev, st2.st_ino) != (st.st_dev, st.st_ino)
            or not stat.S_ISDIR(st2.st_mode)
        ):
            logger.debug(
                "tmp reaper: %s changed identity between validation "
                "and delete; skipping this sweep", path,
            )
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
        30 days, 0 disables), judged by the run's END timestamp (when
        it failed), falling back to the start timestamp — clamped by
        the dir mtime so a freshly SWEEP-failed old run (sweeps record
        no end_timestamp) gets a full window, not instant deletion —
        see :func:`_run_age_seconds`.
      - In-use probe before deletion: a dir some live process has as
        its cwd (or with a socket still answering) is skipped.
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
    live_cwds: set[str] | None = None
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
        # Bounded load (st_size gate before read): the sweep runs at
        # the start of every run over whatever the parent dir holds,
        # so a planted multi-GiB metadata file must not be buffered
        # just to decide reapability. Oversize/malformed/unreadable
        # all degrade to None → skip, matching the old best-effort
        # except-continue behaviour.
        from core.json.utils import load_json

        meta = load_json(meta_path, max_bytes=_RUN_METADATA_MAX_BYTES)
        if not isinstance(meta, dict):
            continue
        if meta.get("status") not in ("failed", "cancelled"):
            continue
        age = _run_age_seconds(meta, st, now)
        if age < max_age:
            continue
        # In-use probe: a failed status is a claim, not proof nothing
        # is still reading the dir (an operator inspecting the journal,
        # a resume about to flip it back to running). A live process
        # cwd'd inside — or a socket still answering — keeps the dir
        # this sweep, same probes as the tmp sweep.
        if live_cwds is None:
            live_cwds = _live_cwds()
        if _dir_in_use(d, live_cwds):
            continue
        # Everything above was decided against the lstat() snapshot
        # `st`; deletion is by pathname. A writer with access to the
        # parent can swap a different entry into this name between
        # validation and rmtree — e.g. rename a completed sibling
        # here — and the reaper would delete the wrong directory.
        # Narrow that window: re-lstat immediately before deleting
        # and require the same identity (st_dev, st_ino) and still-
        # a-directory; anything swapped in (replacement dir OR
        # symlink — S_ISDIR on lstat is false for a symlink) is
        # skipped this sweep. Below the top level shutil.rmtree's
        # fd-based traversal handles symlinks itself.
        try:
            st2 = d.lstat()
        except OSError:
            continue
        if (
            (st2.st_dev, st2.st_ino) != (st.st_dev, st.st_ino)
            or not stat.S_ISDIR(st2.st_mode)
        ):
            logger.warning(
                "run reaper: %s changed identity between validation "
                "and delete; skipping this sweep", d,
            )
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
    """Age from the run's END timestamp, then start — clamped by the
    dir-mtime evidence (``min``).

    The END timestamp (when the run actually failed / was cancelled)
    comes first: aging from the START deleted a long-lived run right
    after it failed — a multi-week campaign that failed yesterday was
    already "30 days old" by its start stamp, and the next sweep
    rmtree'd its journal and partial results.

    The mtime clamp covers the sweep-failed path: both abandon sweeps
    call ``fail_run(..., record_timing=False)``, which records NO
    ``end_timestamp`` (sweeps make no timing claim) — but their
    metadata rewrite refreshes the dir mtime, so never reporting an
    age older than the mtime evidence restarts the reap window for a
    freshly-swept old-start run instead of deleting it on the very
    next sweep.
    """
    from datetime import datetime, timezone

    mtime_age = now - st.st_mtime
    for key in ("end_timestamp", "timestamp"):
        ts = meta.get(key)
        if not isinstance(ts, str):
            continue
        try:
            stamped = datetime.fromisoformat(ts)
        except ValueError:
            continue
        if stamped.tzinfo is None:
            stamped = stamped.replace(tzinfo=timezone.utc)
        return min(now - stamped.timestamp(), mtime_age)
    return mtime_age


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

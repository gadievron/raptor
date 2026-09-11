"""Opt-in lifecycle hooks for ``cve-env build``.

Helpers are no-ops by default. They fire from ``cli.py:_cmd_build()``'s
``finally`` block only when the corresponding env var (``CVE_ENV_AUTO_*``)
OR CLI flag (``--auto-*``) is set. See ``config.py`` for the env-var →
constant mapping.

Lockfile design: each ``cve-env build`` writes
``<tempdir>/cve-env-locks-<uid>/cve-env-{pid}.lock`` on entry and removes
it on exit (via ``acquire_lock`` / ``release_lock``).
``stop_colima_if_idle()`` consults the lock set; ``colima stop`` only fires
when no OTHER active builds are present (own PID excluded; stale-PID locks
are cleaned up opportunistically as a side-effect of the count).
"""

from __future__ import annotations

import logging
import os
import stat
import tempfile
from pathlib import Path

from cve_env.config import CVE_LABEL
from cve_env.utils.run import run_with_timeout

logger = logging.getLogger(__name__)

# Locks live in a per-user 0o700 subdirectory, NOT directly in the shared
# temp dir: the lock names are predictable (PID-scoped), so in a
# world-writable directory a hostile local user could pre-plant symlinks
# (redirecting any write through the name) or fake live-PID locks (to
# suppress the idle auto-stop). The private directory removes the shared
# namespace entirely; ownership is validated before use.
LOCK_DIR = Path(tempfile.gettempdir()) / f"cve-env-locks-{os.getuid()}"
LOCK_PREFIX = "cve-env-"
LOCK_SUFFIX = ".lock"


def _ensure_lock_dir() -> Path:
    """Create/validate the private lock directory; raises if it exists
    but is a symlink or owned by another user (a planted directory)."""
    d = LOCK_DIR
    d.mkdir(mode=0o700, exist_ok=True)
    st = os.stat(d, follow_symlinks=False)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid():
        msg = f"lock dir {d} is not a directory owned by this user"
        raise RuntimeError(msg)
    return d


def acquire_lock() -> Path:
    """Create a per-PID lockfile so concurrent builds can be detected.
    Caller must invoke :func:`release_lock` on the returned path before exit.

    Exclusive no-follow create only. A stale lock from a recycled PID is
    unlinked and re-created through the same ``O_EXCL | O_NOFOLLOW`` open
    — never written through the existing name, which would follow a
    planted symlink and overwrite whatever it points at.
    """
    path = _ensure_lock_dir() / f"{LOCK_PREFIX}{os.getpid()}{LOCK_SUFFIX}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    try:
        fd = os.open(str(path), flags, 0o644)
    except FileExistsError:
        logger.warning("stale lockfile %s already exists; replacing", path)
        path.unlink(missing_ok=True)
        fd = os.open(str(path), flags, 0o644)
    try:
        os.write(fd, str(os.getpid()).encode())
    finally:
        os.close(fd)
    return path


def release_lock(path: Path) -> None:
    """Remove a lockfile. No-op if already gone."""
    path.unlink(missing_ok=True)


def count_other_active_builds() -> int:
    """Count cve-env build processes other than this one.

    Reads the private lock directory's ``cve-env-*.lock`` files. Stale
    locks (PIDs no longer alive) are removed opportunistically —
    counting acts as a sweep.
    """
    own_pid = os.getpid()
    count = 0
    for path in LOCK_DIR.glob(f"{LOCK_PREFIX}*{LOCK_SUFFIX}"):
        stem = path.stem  # e.g. "cve-env-12345"
        if not stem.startswith(LOCK_PREFIX):
            continue
        try:
            pid = int(stem[len(LOCK_PREFIX) :])
        except ValueError:
            continue
        if pid == own_pid:
            continue
        try:
            # os.kill(pid, 0) may succeed for a recycled PID. Low risk:
            # PID recycling window is small relative to build duration.
            os.kill(pid, 0)
        except ProcessLookupError:
            path.unlink(missing_ok=True)
        except PermissionError:
            count += 1
        else:
            count += 1
    return count


def cleanup_containers(cve_id: str, timeout: float = 30.0) -> int:
    """Remove docker containers labeled with this CVE id.

    Returns the count of containers removed (0 if none matched). Empty
    ``cve_id`` is a no-op (returns 0).

    The filter keys on the ``cve-env.cve-id`` label. cli.py's ``run_id``
    (e.g. ``manual-{ts}``) and the agent-passed ``run_id`` in docker_run
    tool calls (e.g. ``cve-env-{cve_id_slug}``) are two different things,
    so a run-id filter would never match. ``cve.cve_id`` is the natural
    unit anyway: one ``cve-env build`` invocation processes exactly one
    CVE.

    Caveat: two parallel ``cve-env build`` invocations on the SAME
    ``cve_id`` would over-clean each other. The common case (sequential
    bench, single-user) is safe.
    """
    from core.container.lifecycle import remove_labeled_containers

    return remove_labeled_containers(CVE_LABEL, cve_id, timeout=timeout)


def cleanup_result_images(cve_id: str, timeout: float = 30.0) -> int:
    """Remove docker IMAGES labeled with this CVE id (sibling of cleanup_containers).

    docker_build labels every built image ``cve-env.cve-id=<id>``
    (docker_build.CVE_LABEL). ``prune_images`` only prunes DANGLING
    layers, leaving the tagged ``cve-env-local:*`` result images to
    accumulate (tens of GB across a bench → Colima disk floor → bench
    stalls). This removes THIS CVE's result images by label — exact
    scope, NO cross-CVE/concurrent collision (other CVEs carry different
    labels).

    Removes by TAG (not ``-f`` by ID) so a multi-tag image (e.g. ``CVE-X`` +
    ``CVE-X-v2``) deletes cleanly as its last tag goes; ``<none>`` rows are
    skipped (left for ``prune_images``) and duplicate tags deduped. Returns
    the count of tags removed. Empty ``cve_id`` is a no-op (returns 0). Call
    AFTER ``cleanup_containers`` so no live container holds the image.

    Kill-path fallback: a SIGKILL'd build (wall-guard timeout) can leave a
    tagged ``cve-env-local:<cve_id>*`` image WITHOUT the ``cve-env.cve-id``
    label, so the label query above misses it. A second query lists all
    ``cve-env-local`` images and keeps those whose TAG is this cve_id (exact
    or ``<cve_id>-*`` suffix — matches the cve-id-scoped default tag and agent
    ``-vN`` variants). Concurrency-safe: scoped to THIS cve_id only, so a
    different concurrent CVE's image is never touched.
    """
    from core.container.lifecycle import remove_labeled_images

    return remove_labeled_images(
        CVE_LABEL,
        cve_id,
        tag_repo="cve-env-local",
        tag_value=cve_id,
        timeout=timeout,
    )


def prune_images(timeout: float = 30.0) -> None:
    """Prune dangling images only — safe against in-use images and current
    tag-references. For aggressive pruning, run ``docker system prune -a``
    manually."""
    from core.container.lifecycle import prune_dangling_images

    prune_dangling_images(timeout=timeout)


def stop_colima_if_idle(timeout: float = 30.0) -> bool:
    """Stop Colima IFF no other cve-env builds are running.

    Returns True if ``colima stop`` was attempted, False if skipped due to
    concurrent activity. Own PID lock should be released by the caller
    BEFORE invoking this so the idle check excludes us.

    Known limitation (TOCTOU): there's a small race window between
    ``count_other_active_builds()`` returning 0 and the ``colima stop``
    subprocess launching, during which a new ``cve-env build`` could
    start and find Colima mid-shutdown. macOS lacks a portable ``flock``,
    so this best-effort design accepts the rare race rather than depend
    on a third-party lock binary. Safe for the common single-user case.
    """
    if count_other_active_builds() > 0:
        logger.info("colima stop SKIPPED: other cve-env builds detected")
        return False
    run_with_timeout(["colima", "stop"], timeout=timeout)
    return True

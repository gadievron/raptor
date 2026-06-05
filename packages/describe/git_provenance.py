"""Git provenance for /describe — branch / commit / dirty /
last-commit-date for the SCANNED TARGET.

Distinct from ``core/run/provenance.py`` which snapshots the
*framework*'s own checkout (the RAPTOR repo that produced a
run). Here the target is attacker-controlled (we're describing
an unknown codebase), so every git call goes through the
shared ``_git`` helper with ``untrusted=True`` — that layers
``safe_git_command``'s per-invocation overrides which
neutralise hostile ``.git/config`` vectors
(``core.fsmonitor`` / ``core.hooksPath`` / CVE-2024-32002
family).

Best-effort throughout: a non-git target, a missing git
binary, a timeout, or any individual command failure yields
``None`` for the affected field rather than failing the
inference. /describe's render shows a "Git: none detected"
line in the all-None case, otherwise renders the fields it
got.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class GitProvenance:
    """Point-in-time git facts for the target tree. All
    fields ``None`` when the target isn't a git checkout (or
    git is unavailable, or every call timed out)."""
    branch: Optional[str]           # current branch name; None when detached HEAD
    commit_short: Optional[str]     # 7-12 char SHA
    dirty: Optional[bool]           # True/False, or None when status couldn't be read
    last_commit_date: Optional[str]  # ISO 8601 (e.g. "2026-05-30T14:22:11+00:00")


def detect_git_provenance(target_path: Path) -> GitProvenance:
    """Snapshot the target's git state. Reuses
    ``core.run.provenance._git`` with ``untrusted=True`` for
    the hostile-.git/config defense.
    """
    try:
        from core.run.provenance import _git
    except Exception:  # noqa: BLE001
        return GitProvenance(None, None, None, None)

    # rev-parse --short = "is this a git checkout AND give me the SHA". A
    # None result means "not a git tree" — short-circuit the rest.
    sha = _git(target_path, "rev-parse", "--short", "HEAD", untrusted=True)
    if sha is None:
        return GitProvenance(None, None, None, None)

    # symbolic-ref returns the branch name; detached HEAD returns None.
    # "main" / "master" / "develop" etc.
    branch = _git(
        target_path, "symbolic-ref", "--short", "HEAD", untrusted=True,
    )

    # status --porcelain is empty on clean. Distinguish "couldn't read" (None)
    # from "clean" (empty) from "dirty" (non-empty).
    status = _git(target_path, "status", "--porcelain", untrusted=True)
    if status is None:
        dirty: Optional[bool] = None
    else:
        dirty = bool(status)

    # %cI = strict ISO 8601 committer date. Parseable by every datetime
    # library; readable by humans.
    last_commit = _git(
        target_path, "log", "-1", "--format=%cI", "HEAD", untrusted=True,
    )

    return GitProvenance(
        branch=branch,
        commit_short=sha,
        dirty=dirty,
        last_commit_date=last_commit,
    )


__all__ = ["GitProvenance", "detect_git_provenance"]

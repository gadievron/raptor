"""Content-free working-tree dirtiness probe for TARGET repositories.

A scanned target can arrive with its own hostile ``.git``: a committed
``* filter=x`` .gitattributes plus a ``filter.x.clean`` command in
``.git/config`` turns any probe that re-hashes worktree content into
command execution at the operator's uid, and the filter's config key
is repo-chosen so no finite ``-c`` override list neutralises it (the
KNOWN LIMIT in ``core.git.clone``). ``git status`` re-hashes via the
index refresh — but so do the plumbing commands folklore calls safe:
``git diff-index HEAD`` (worktree side), ``diff-files`` and
``ls-files -m`` all re-READ file content through the filter chain for
*racily clean* entries (cached mtime not older than the index's own
mtime), and the racy window is attacker-controllable because the
hostile repo ships its own index — every entry can be crafted racy.

The only git surface that never opens worktree files is: index/HEAD
comparison (``diff-index --cached``), index dumps (``ls-files``,
``ls-files --debug``), tree dumps (``ls-tree``), and the
``ls-files --others`` directory walk. So worktree-vs-index change
detection happens HERE, in Python: each index entry's cached stat
data (``ls-files --debug``) is compared against ``os.lstat`` — the
same size/mtime test git itself applies, minus the content
re-verification of racy entries.

Accepted trade-offs (all in the conservative, fail-closed direction
except the last two, which need an attacker-grade coincidence):

* a stat-touched but content-identical file counts dirty;
* a sparse-checkout / skip-worktree entry with no file on disk counts
  dirty;
* a same-size edit landing in the same mtime nanosecond is missed;
* chmod-only changes are missed (the stat dump carries no mode).
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from core.git.clone import get_safe_git_env, safe_git_readonly_command

logger = logging.getLogger(__name__)

__all__ = ["WorktreeDirt", "probe_worktree_dirt"]

# One ``ls-files --debug -z`` entry: NUL-terminated raw path (no
# quoting, embedded newlines stay literal) followed by git's
# fixed-shape stat block. Matches must tile the output exactly —
# any gap means an unrecognised format and the probe fails closed.
_DEBUG_ENTRY_RE = re.compile(
    rb"(?P<path>[^\0]+)\0"
    rb"  ctime: \d+:\d+\n"
    rb"  mtime: (?P<msec>\d+):(?P<mnsec>\d+)\n"
    rb"  dev: \d+\tino: \d+\n"
    rb"  uid: \d+\tgid: \d+\n"
    rb"  size: (?P<size>\d+)\tflags: \S+\n"
)

# Index stat fields are truncated to 32 bits on disk; mask both sides
# of every comparison.
_U32 = 0xFFFFFFFF


@dataclass(frozen=True)
class WorktreeDirt:
    """Dirty-path listing per channel; a ``None`` channel means that
    probe failed (not "clean" — never guessed)."""

    tracked: tuple[str, ...] | None    # staged or worktree-modified
    untracked: tuple[str, ...] | None  # ls-files --others listing

    @property
    def dirty(self) -> bool | None:
        """True on any observed dirt; None when a channel failed and
        no dirt was seen elsewhere (unknowable, never claimed clean);
        False only when BOTH channels answered and both are empty."""
        if self.tracked or self.untracked:
            return True
        if self.tracked is None or self.untracked is None:
            return None
        return False


def _run_git(repo: Path, args: tuple[str, ...],
             timeout: float) -> bytes | None:
    """One read-only git listing against the target; None on failure."""
    try:
        proc = subprocess.run(
            safe_git_readonly_command(*args),
            cwd=repo,
            capture_output=True,
            timeout=timeout,
            check=False,
            env=get_safe_git_env(),
        )
    except (subprocess.SubprocessError, OSError) as exc:
        logger.debug("git dirty probe: %s failed for %s: %s",
                     args[0], repo, exc)
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout


def _staged_paths(repo: Path, timeout: float) -> set[bytes] | None:
    """Paths whose INDEX entry differs from HEAD (index-vs-tree only —
    never touches worktree content)."""
    out = _run_git(
        repo,
        ("diff-index", "--cached", "--no-ext-diff", "--name-only",
         "-z", "HEAD"),
        timeout,
    )
    if out is None:
        return None
    return {tok for tok in out.split(b"\0") if tok}


def _stat_dirty_paths(repo: Path, timeout: float) -> set[bytes] | None:
    """Paths whose on-disk stat no longer matches the index's cached
    stat data — modified, deleted, or replaced tracked files."""
    out = _run_git(repo, ("ls-files", "--debug", "-z"), timeout)
    if out is None:
        return None
    repo_b = os.fsencode(repo)
    dirty: set[bytes] = set()
    pos = 0
    for match in _DEBUG_ENTRY_RE.finditer(out):
        if match.start() != pos:
            return None  # unrecognised interleaved output — fail closed
        pos = match.end()
        path = match.group("path")
        try:
            st = os.lstat(os.path.join(repo_b, path))
        except OSError:
            dirty.add(path)  # deleted / unstat-able tracked file
            continue
        size = int(match.group("size"))
        msec = int(match.group("msec"))
        mnsec = int(match.group("mnsec"))
        st_sec, st_nsec = divmod(st.st_mtime_ns, 10 ** 9)
        if (st.st_size & _U32) != size or (st_sec & _U32) != msec:
            dirty.add(path)
        elif mnsec != 0 and mnsec != st_nsec:
            # nsec is compared only when the index recorded one —
            # git builds without nanosecond support store 0 there.
            dirty.add(path)
    if pos != len(out):
        return None  # trailing unparsed bytes — fail closed
    return dirty


def _untracked_paths(repo: Path, timeout: float) -> set[bytes] | None:
    """Untracked, not-ignored files (pure directory walk)."""
    out = _run_git(
        repo, ("ls-files", "--others", "--exclude-standard", "-z"),
        timeout,
    )
    if out is None:
        return None
    return {tok for tok in out.split(b"\0") if tok}


def probe_worktree_dirt(repo: Path, *,
                        timeout: float = 15) -> WorktreeDirt:
    """Probe the target's uncommitted state without ever letting git
    open a worktree file (see module docstring for why that matters).

    Never raises; a failed channel comes back as ``None`` and the
    ``dirty`` property degrades to ``None`` rather than guessing.
    """
    staged = _staged_paths(repo, timeout)
    stat_dirty = _stat_dirty_paths(repo, timeout)
    if staged is None or stat_dirty is None:
        tracked: tuple[str, ...] | None = None
    else:
        tracked = tuple(sorted(os.fsdecode(p) for p in staged | stat_dirty))
    raw_untracked = _untracked_paths(repo, timeout)
    if raw_untracked is None:
        untracked: tuple[str, ...] | None = None
    else:
        untracked = tuple(sorted(os.fsdecode(p) for p in raw_untracked))
    return WorktreeDirt(tracked=tracked, untracked=untracked)

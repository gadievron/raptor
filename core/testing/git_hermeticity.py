"""Git hermeticity substrate for the test session.

Two invariants, enforced from the root ``conftest.py``:

1. **Operator git config must not leak into tests** (and tests must not
   depend on it): ``GIT_CONFIG_GLOBAL``/``GIT_CONFIG_SYSTEM`` are pinned
   to ``/dev/null`` for the whole session, and ambient ``GIT_*``
   identity/redirection variables are stripped.  Hermeticity is
   two-directional — the same pinning also stops a test's ``git config
   --global`` from ever reaching the operator's real global config.

2. **Tests must not mutate the ambient checkout's repo-level git
   config**: the config file(s) that a repo-level ``git config`` write
   from inside this checkout would land in are fingerprinted at session
   start and compared at session end.  A drift means some test ran git
   against the real checkout instead of its tmp fixture (the exact
   incident class: a fixture ``cd`` failed and ``git config user.name
   "Test"`` walked into the operator's ``.git/config``).

Fixture repos themselves should be built with
:mod:`core.testing.gitrepo` — this module only guards the session.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path
from collections.abc import MutableMapping

#: Forced for the whole test session (not ``setdefault`` — hermeticity
#: must hold even when the operator exports their own values).
GIT_ENV_PINS: dict[str, str] = {
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_SYSTEM": "/dev/null",
}

#: Ambient variables that would redirect or re-identify every git
#: invocation in the session — stripped at session start.  Tests that
#: need one set it explicitly on their own subprocess env.
GIT_ENV_STRIP: tuple[str, ...] = (
    "GIT_AUTHOR_NAME",
    "GIT_AUTHOR_EMAIL",
    "GIT_AUTHOR_DATE",
    "GIT_COMMITTER_NAME",
    "GIT_COMMITTER_EMAIL",
    "GIT_COMMITTER_DATE",
    "GIT_CONFIG_PARAMETERS",
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_COMMON_DIR",
    "GIT_NAMESPACE",
    "GIT_CEILING_DIRECTORIES",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    # Aligned with the product's DANGEROUS_ENV_VARS taxonomy
    # (core/config get_safe_env): a template dir injects hooks into
    # every fixture ``git init``; an exec path substitutes git-<cmd>
    # helpers wholesale.
    "GIT_TEMPLATE_DIR",
    "GIT_EXEC_PATH",
)

#: Prefix family for ``GIT_CONFIG_COUNT``-style injection
#: (``GIT_CONFIG_KEY_0`` / ``GIT_CONFIG_VALUE_0`` / …).
GIT_ENV_STRIP_PREFIXES: tuple[str, ...] = (
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_KEY_",
    "GIT_CONFIG_VALUE_",
)


def pin_git_env(environ: MutableMapping[str, str] = os.environ,
                ) -> dict[str, str | None]:
    """Apply the pins/strips to *environ*; return the displaced
    originals (``None`` marks a variable that was unset) so an escape
    hatch can restore them for a single test."""
    saved: dict[str, str | None] = {}
    strip = list(GIT_ENV_STRIP) + [
        k for k in environ
        if any(k.startswith(p) for p in GIT_ENV_STRIP_PREFIXES)
    ]
    for key in strip:
        saved[key] = environ.pop(key, None)
    for key, value in GIT_ENV_PINS.items():
        saved[key] = environ.get(key)
        environ[key] = value
    return saved


def restore_git_env(saved: dict[str, str | None],
                    environ: MutableMapping[str, str] = os.environ,
                    ) -> None:
    """Undo :func:`pin_git_env` (used by the escape-hatch marker)."""
    for key, value in saved.items():
        if value is None:
            environ.pop(key, None)
        else:
            environ[key] = value


def repo_config_paths(checkout: Path) -> list[Path]:
    """The config file(s) a repo-level ``git config`` write from inside
    *checkout* lands in.

    For a plain checkout this is ``.git/config``; for a linked worktree
    it is the COMMON dir's config (repo-level writes are shared), plus
    ``config.worktree`` when the worktree-config extension is in use.
    Returns ``[]`` when *checkout* is not inside a git repo or git is
    unavailable — callers skip silently, matching the tree-drift
    fingerprint convention.
    """
    try:
        proc = subprocess.run(
            ["git", "-C", str(checkout), "rev-parse",
             "--path-format=absolute", "--git-common-dir",
             "--absolute-git-dir"],
            capture_output=True, text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if proc.returncode != 0:
        return []
    lines = proc.stdout.splitlines()
    if len(lines) != 2:
        return []
    common_dir, git_dir = (Path(line) for line in lines)
    paths = [common_dir / "config"]
    worktree_config = git_dir / "config.worktree"
    if worktree_config != paths[0] and worktree_config.exists():
        paths.append(worktree_config)
    return paths


def config_fingerprint(checkout: Path) -> dict[str, str | None] | None:
    """sha256 per config file (``None`` value = file absent,
    ``"unreadable"`` = exists but cannot be read — a permission flip is
    itself a drift, not a reason to go quiet).  Returns ``None`` only
    when there is nothing to guard (no repo / no git on PATH /
    pre-2.31 git without ``--path-format``) — the caller must then skip
    the check rather than report a bogus drift.  Read-only: never
    creates or touches the files it hashes."""
    paths = repo_config_paths(checkout)
    if not paths:
        return None
    fingerprint: dict[str, str | None] = {}
    for path in paths:
        try:
            fingerprint[str(path)] = hashlib.sha256(
                path.read_bytes()).hexdigest()
        except FileNotFoundError:
            fingerprint[str(path)] = None
        except OSError:
            fingerprint[str(path)] = "unreadable"
    return fingerprint


def describe_drift(start: dict[str, str | None],
                   end: dict[str, str | None]) -> list[str]:
    """Human-readable per-file drift lines (empty = no drift)."""
    def _fmt(digest: str | None) -> str:
        return "absent" if digest is None else digest[:16]

    lines = []
    for path in sorted(set(start) | set(end)):
        before = start.get(path)
        after = end.get(path)
        if before == after:
            continue
        lines.append(f"{path}: {_fmt(before)} -> {_fmt(after)}")
    return lines


__all__ = [
    "GIT_ENV_PINS",
    "GIT_ENV_STRIP",
    "GIT_ENV_STRIP_PREFIXES",
    "config_fingerprint",
    "describe_drift",
    "pin_git_env",
    "repo_config_paths",
    "restore_git_env",
]

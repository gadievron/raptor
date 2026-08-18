"""Hermetic git fixture repos for tests.

Consolidates the ``_git()`` / ``_init_repo()`` helper pairs test
suites re-spelled in at least five dialects — with real drift: some
copies inherited the operator's global gitconfig (flaky on hosts with
``init.defaultBranch``, ``commit.gpgsign=true``, or hooks), some
pinned identity via env vars, some via ``git config`` writes into the
repo, and only a few pinned the default branch name.

This is the union of the hermetic behaviours:

* ``HOME`` redirected + ``GIT_CONFIG_GLOBAL``/``GIT_CONFIG_SYSTEM``
  pointed at ``/dev/null`` — no operator config can leak in;
* identity supplied per-invocation via ``-c user.name/user.email``
  (no repo-state mutation, works for every subcommand);
* ``-c commit.gpgsign=false`` — hosts with signing enabled globally
  can't hang the suite on a key prompt;
* ``git init -b main`` — deterministic default-branch name.

FIXTURE SETUP ONLY (RAPTOR-authored content): production code paths
touching untrusted repos go through ``core.git`` hardening, never
through this module.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

DEFAULT_BRANCH = "main"

_IDENTITY_FLAGS = (
    "-c", "user.name=fixture",
    "-c", "user.email=fixture@example.invalid",
    "-c", "commit.gpgsign=false",
)


def _hermetic_env(home: Path) -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(home),
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
    }


def git_run(repo: Path, *args: str) -> str:
    """Run one hermetic git command in *repo*; return stripped stdout.

    ``check=True`` — fixture setup must fail loudly, not produce a
    half-built repo the test then mis-diagnoses.
    """
    proc = subprocess.run(
        ["git", "-C", str(repo), *_IDENTITY_FLAGS, *args],
        check=True,
        capture_output=True,
        text=True,
        env=_hermetic_env(repo.parent),
    )
    return proc.stdout.strip()


def init_scratch_repo(tmp_path: Path, name: str = "repo") -> Path:
    """Create ``tmp_path/name`` and ``git init`` it hermetically with
    a deterministic default branch. Returns the repo path; commit
    fixture content with :func:`git_run`.
    """
    repo = tmp_path / name
    repo.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "init", "-q", "-b", DEFAULT_BRANCH, str(repo)],
        check=True,
        capture_output=True,
        env=_hermetic_env(tmp_path),
    )
    return repo


__all__ = ["DEFAULT_BRANCH", "git_run", "init_scratch_repo"]

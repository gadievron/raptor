"""
Commit resolver — validate and normalize commit refs before expensive work.

Ported from code-differ/packages/patch_analysis/commit_resolver.py.

Core guarantees:
- `before != after` before a diff is even attempted (Bug #12 fallout: a fallback
  path used to silently diff `HEAD..HEAD` producing empty output claimed as
  success).
- `^`, `^^`, `^N` parent suffixes stripped to a plain SHA before we call git;
  git itself accepts them but our type `CommitSha` represents a *terminal* SHA.
- Short SHAs → full SHAs via `git rev-parse` when a local clone is available.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from cve_diff.core.exceptions import IdenticalCommitsError
from cve_diff.core.models import CommitSha

_SHA_RE = re.compile(r"^[a-f0-9]{7,40}$", re.IGNORECASE)
_INVALID_LITERALS = frozenset({"0", "none", "null", ""})
# git's canonical empty-tree SHA; `git diff <empty-tree>..<root-commit>`
# produces the full-file-as-added diff. Used when a fix commit is the first
# commit in a repository (e.g. CVE-2024-3094 in tukaani-project/xz).
_GIT_EMPTY_TREE_SHA = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


@dataclass
class CommitResolver:
    def strip_parent_notation(self, commit: str) -> str:
        """`abc^` → `abc`, `abc^^2` → `abc`, `abc~3` → `abc`."""
        return re.sub(r"[\^~].*$", "", commit)

    def is_valid_sha_format(self, commit: str | None) -> bool:
        if commit is None:
            return False
        normalized = str(commit).strip().lower()
        if normalized in _INVALID_LITERALS:
            return False
        return bool(_SHA_RE.match(normalized))

    def validate_different(self, before: str | None, after: str | None) -> None:
        if before is None or after is None:
            return
        if before.lower() == after.lower():
            raise IdenticalCommitsError(
                f"commit_before ({before}) equals commit_after ({after}) — cannot diff."
            )

    def expand(self, repo_path: Path, commit: str) -> CommitSha:
        """Resolve abbreviated SHAs via `git rev-parse` in a local clone."""
        clean = self.strip_parent_notation(commit)
        if not self.is_valid_sha_format(clean):
            raise ValueError(f"Not a SHA: {commit!r}")
        try:
            completed = subprocess.run(
                ["git", "-C", str(repo_path), "rev-parse", clean],
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
        except subprocess.TimeoutExpired as exc:
            raise ValueError(f"git rev-parse {clean!r} timed out") from exc
        if completed.returncode != 0:
            raise ValueError(
                f"git rev-parse {clean!r} failed: {completed.stderr.strip()}"
            )
        return CommitSha(completed.stdout.strip())

    def parent_of(self, repo_path: Path, commit: str) -> CommitSha:
        """Return the first-parent SHA of `commit`. Used when `introduced` is absent.

        For a root commit (no parent), returns git's empty-tree SHA so callers
        can still produce a full-file-as-added diff.
        """
        clean = self.strip_parent_notation(commit)
        if not self.is_valid_sha_format(clean):
            raise ValueError(f"Not a SHA: {commit!r}")
        try:
            completed = subprocess.run(
                ["git", "-C", str(repo_path), "rev-parse", f"{clean}^"],
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
        except subprocess.TimeoutExpired as exc:
            raise ValueError(
                f"git rev-parse {clean}^ timed out"
            ) from exc
        if completed.returncode != 0:
            if self._is_root_commit(repo_path, clean):
                return CommitSha(_GIT_EMPTY_TREE_SHA)
            raise ValueError(
                f"git rev-parse {clean}^ failed: {completed.stderr.strip()}"
            )
        return CommitSha(completed.stdout.strip())

    @staticmethod
    def _is_root_commit(repo_path: Path, sha: str) -> bool:
        try:
            result = subprocess.run(
                ["git", "-C", str(repo_path), "rev-list", "--max-parents=0", "--all"],
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
        except subprocess.TimeoutExpired:
            return False
        if result.returncode != 0:
            return False
        roots = {line.strip() for line in result.stdout.splitlines() if line.strip()}
        return sha in roots

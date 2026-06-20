"""
Git Client for local forensic analysis.
"""
from __future__ import annotations

import subprocess
from typing import Any

from ..schema.common import EvidenceSource


class GitClient:
    """Client for local git operations."""

    def __init__(self, repo_path: str = "."):
        self.repo_path = repo_path

    @property
    def source(self) -> EvidenceSource:
        return EvidenceSource.GIT

    def _run(self, *args: str) -> str:
        try:
            result = subprocess.run(
                ["git", "-C", self.repo_path, *args],
                capture_output=True,
                text=True,
                check=True,
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            # Enhance error message with stderr
            raise RuntimeError(f"Git command failed: {' '.join(args)}\nError: {e.stderr}") from e

    def get_commit(self, sha: str) -> dict[str, Any]:
        """Get commit info from local git."""
        # %H: commit hash
        # %an: author name
        # %ae: author email
        # %aI: author date, strict ISO 8601 format
        # %cn: committer name
        # %ce: committer email
        # %cI: committer date, strict ISO 8601 format
        # %P: parent hashes
        # %B: raw body (unwrapped subject and body)
        format_str = "%H%n%an%n%ae%n%aI%n%cn%n%ce%n%cI%n%P%n%B"
        output = self._run("show", "-s", f"--format={format_str}", sha)
        lines = output.split("\n")

        return {
            "sha": lines[0],
            "author_name": lines[1],
            "author_email": lines[2],
            "author_date": lines[3],
            "committer_name": lines[4],
            "committer_email": lines[5],
            "committer_date": lines[6],
            "parents": lines[7].split() if lines[7] else [],
            "message": "\n".join(lines[8:]),
        }

    def get_commit_files(self, sha: str) -> list[dict[str, Any]]:
        """Get files changed in a commit."""
        # --no-commit-id: output only the changes
        # --name-status: show only names and status of changed files
        # -r: recursive
        output = self._run("diff-tree", "--no-commit-id", "--name-status", "-r", sha)
        files = []
        for line in output.split("\n"):
            if line:
                parts = line.split("\t")
                status_map = {"A": "added", "M": "modified", "D": "removed", "R": "renamed"}
                files.append({"status": status_map.get(parts[0][0], "modified"), "filename": parts[-1]})
        return files

    def get_log(
        self,
        ref: str = "HEAD",
        since: str | None = None,
        until: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Get commit log."""
        args = ["log", f"--max-count={limit}", "--format=%H|%an|%ae|%aI|%s", ref]
        if since:
            args.append(f"--since={since}")
        if until:
            args.append(f"--until={until}")

        output = self._run(*args)
        commits = []
        for line in output.split("\n"):
            if line:
                parts = line.split("|", 4)
                commits.append(
                    {
                        "sha": parts[0],
                        "author_name": parts[1],
                        "author_email": parts[2],
                        "author_date": parts[3],
                        "message": parts[4] if len(parts) > 4 else "",
                    }
                )
        return commits

    def fsck(self) -> str:
        """Run git fsck to find integrity issues and dangling objects."""
        # git fsck returns status code 0 even if it finds issues, 
        # but prints to stdout/stderr.
        # We want to capture everything.
        result = subprocess.run(
            ["git", "-C", self.repo_path, "fsck", "--full"],
            capture_output=True,
            text=True,
            check=False 
        )
        return result.stdout + result.stderr

    def cat_file(self, object_sha: str) -> str:
        """Get raw content of an object."""
        return self._run("cat-file", "-p", object_sha)

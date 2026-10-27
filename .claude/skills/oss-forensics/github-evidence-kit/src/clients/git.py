"""
Git Client for local forensic analysis.
"""
from __future__ import annotations

import os
import re
import subprocess
from typing import Any

from ..schema.common import EvidenceSource

# SHAs and refs reaching this client are harvested from
# attacker-authored sources (GH Archive payloads, vendor reports,
# archived pages), and git treats a leading-dash positional as an
# option — e.g. a "sha" of `--output=/path` makes `git show` write an
# arbitrary file. Two layers, both required: validate the value shape
# here, and pass `--end-of-options` before every positional revision
# in the callers so git never option-parses one (supported since git
# 2.24).

# Full or abbreviated hex object name; 64 covers SHA-256 repos.
_HEX_SHA_RE = re.compile(r"^[0-9a-fA-F]{4,64}$")

# Characters git check-ref-format forbids anywhere in a refname.
_REF_FORBIDDEN_CHARS = set(' ~^:?*[\\')


def _validate_sha(sha: str) -> str:
    if not _HEX_SHA_RE.fullmatch(sha):
        msg = f"invalid git object name (expected 4-64 hex chars): {sha!r}"
        raise ValueError(msg)
    return sha


def _validate_ref(ref: str) -> str:
    """Refuse refs that violate git check-ref-format rules (plus the
    option-shape leading dash). Conservative: symbolic names like HEAD
    and one-level branch names pass; revision operators (~, ^, :) and
    anything option- or traversal-shaped fail closed."""
    ok = (
        bool(ref)
        and not ref.startswith(("-", "/"))
        and not ref.endswith(("/", "."))
        and ref != "@"
        and "@{" not in ref
        and ".." not in ref
        and "//" not in ref
    )
    if ok:
        for ch in ref:
            if ord(ch) < 0x20 or ord(ch) == 0x7F or ch in _REF_FORBIDDEN_CHARS:
                ok = False
                break
    if ok:
        for component in ref.split("/"):
            if component.startswith(".") or component.endswith(".lock"):
                ok = False
                break
    if not ok:
        msg = f"invalid git ref: {ref!r}"
        raise ValueError(msg)
    return ref


def _validate_revision(rev: str) -> str:
    """A commit-ish argument: a hex object name or a symbolic name
    (``HEAD``, a branch/tag) that passes the ref rules. Existing
    callers pass either, so both stay accepted; option-shaped and
    otherwise hostile values fail closed."""
    if _HEX_SHA_RE.fullmatch(rev):
        return rev
    try:
        return _validate_ref(rev)
    except ValueError:
        msg = f"invalid git revision (not a hex object name or ref): {rev!r}"
        raise ValueError(msg) from None

# Per-invocation `-c` overrides that defang malicious settings the
# investigated REPO can plant in its own .git/config — env vars alone
# can't suppress per-repo config. Mirrors core.git.clone.
# _SAFE_GIT_READONLY_OVERRIDES; inlined because this skill module has
# no core/ import. When core's list grows, this copy must grow with
# it (consolidation pending).
#
# Threats neutralised:
#   - core.fsmonitor=<cmd>: arbitrary command on every git invocation
#     (CVE-2024-32002 family). Setting `core.fsmonitor=` (empty)
#     refuses the override.
#   - core.editor / core.pager: launch attacker-named editor or
#     pager on commit/log/blame.
#   - core.askPass: spawn askpass binary for credential prompts.
#   - core.hooksPath=/dev/null: hostile per-repo hooks directory —
#     fires arbitrary scripts on git ops without it.
#   - credential.helper= / core.gitProxy=: per-repo helper/proxy
#     command RCE (CVE-2017-1000117 family).
#   - gpg.program=true (+ x509/ssh variants): log/show with %G?
#     formats would exec a repo-named signature verifier per commit.
#   - diff.external=: repo-named external diff driver. This client
#     only runs object-DB reads (show -s, diff-tree --name-status,
#     log --format, cat-file, fsck) which never render content
#     diffs, so no --no-ext-diff is needed.
#   - protocol.allow=never (+ file/ext pins) and
#     core.sshCommand=false: every command here is a local read-only
#     operation — no transport is ever legitimate, so all of them
#     are refused wholesale (strict read-only posture).
_SAFE_GIT_OVERRIDES = (
    "-c", "core.fsmonitor=",
    "-c", "core.editor=true",
    "-c", "core.pager=cat",
    "-c", "core.askPass=true",
    "-c", "core.hooksPath=/dev/null",
    "-c", "credential.helper=",
    "-c", "core.gitProxy=",
    "-c", "gpg.program=true",
    "-c", "gpg.x509.program=true",
    "-c", "gpg.ssh.program=true",
    "-c", "diff.external=",
    "-c", "protocol.allow=never",
    "-c", "protocol.file.allow=never",
    "-c", "protocol.ext.allow=never",
    "-c", "core.sshCommand=false",
)

# Env allowlist for git subprocesses — mirrors the shape of
# core.config get_git_env (allowlist + GIT_* prompt/config pins),
# inlined for the same no-core-import reason. Everything not listed
# is dropped: LD_PRELOAD/GIT_SSH/GIT_EXTERNAL_DIFF etc. must not
# reach a git run against an untrusted repo.
_ENV_ALLOWLIST = ("PATH", "HOME", "USER", "LOGNAME", "TMPDIR", "TZ", "LANG")

_GIT_ENV_PINS = {
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_ASKPASS": "true",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_SYSTEM": "/dev/null",
    "GIT_CONFIG_NOSYSTEM": "1",
}

_GIT_TIMEOUT_S = 120


def _safe_git_env() -> dict[str, str]:
    env = {
        k: v for k, v in os.environ.items()
        if k in _ENV_ALLOWLIST or k.startswith("LC_")
    }
    env.update(_GIT_ENV_PINS)
    return env


class GitClient:
    """Client for local git operations."""

    def __init__(self, repo_path: str = ".") -> None:
        self.repo_path = repo_path

    @property
    def source(self) -> EvidenceSource:
        return EvidenceSource.GIT

    def _run(self, *args: str) -> str:
        try:
            result = subprocess.run(
                ["git", *_SAFE_GIT_OVERRIDES, "-C", self.repo_path, *args],
                capture_output=True,
                text=True,
                check=True,
                timeout=_GIT_TIMEOUT_S,
                env=_safe_git_env(),
            )
            return result.stdout.strip()
        except subprocess.TimeoutExpired as e:
            msg = (
                f"Git command timed out after {_GIT_TIMEOUT_S}s: "
                f"{' '.join(args)}"
            )
            raise RuntimeError(msg) from e
        except subprocess.CalledProcessError as e:
            # Enhance error message with stderr
            msg = f"Git command failed: {' '.join(args)}\nError: {e.stderr}"
            raise RuntimeError(msg) from e

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
        output = self._run(
            "show", "-s", f"--format={format_str}",
            "--end-of-options", _validate_revision(sha),
        )
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
        output = self._run(
            "diff-tree", "--no-commit-id", "--name-status", "-r",
            "--end-of-options", _validate_revision(sha),
        )
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
        all_refs: bool = False,
    ) -> list[dict[str, Any]]:
        """Get commit log."""
        args = ["log", f"--max-count={limit}", "--format=%H|%an|%ae|%aI|%s"]
        if since:
            args.append(f"--since={since}")
        if until:
            args.append(f"--until={until}")
        if all_refs:
            args.append("--all")
        else:
            args.extend(["--end-of-options", _validate_ref(ref)])

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
            ["git", *_SAFE_GIT_OVERRIDES, "-C", self.repo_path, "fsck", "--full"],
            capture_output=True,
            text=True,
            check=False,
            timeout=_GIT_TIMEOUT_S * 5,  # fsck --full walks every object
            env=_safe_git_env(),
        )
        return result.stdout + result.stderr

    def cat_file(self, object_sha: str) -> str:
        """Get raw content of an object."""
        return self._run(
            "cat-file", "-p", "--end-of-options", _validate_revision(object_sha),
        )

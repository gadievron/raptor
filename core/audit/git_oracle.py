"""Local git-history oracle for /audit — CORROBORATION ONLY.

Given a finding's file (and optionally a function line range), query
the LOCAL clone's history for prior security-relevant fixes touching
it: commit subjects/messages matching security-fix patterns (``CVE-``,
``overflow``, ``use-after-free``, ``sanitize``, ...).  The result is
structured corroboration context — commit shas, subjects, dates, files
touched — attached to the review journal for the operator and the LLM.

THIS MODULE NEVER PRODUCES A VERDICT.  By construction:

* it returns :class:`GitCorroboration` / :class:`CorroborationRecord`,
  not ``SweepResult`` — there is no ``outcome`` field to read as
  confirmed/refuted;
* its journal payload is stamped ``kind="corroboration"`` with an
  explicit not-a-verdict note;
* its namespace (``git_history``) is deliberately NOT registered in
  :data:`core.audit.evidence_grade.VALID_EVIDENCE_TOOLS`, so a stamp
  like ``git_history:cve`` can never satisfy ``is_tool_evidence`` and
  can never promote a finding's verification tier.

SECURITY (the scanned repo is UNTRUSTED — git on a hostile clone can
execute repo-controlled code via hooks, fsmonitor, and per-repo
config, CVE-2024-32002 family).  Every git invocation here:

* runs under ``core.sandbox.context.run`` with ``block_network=True``
  plus Landlock target/output confinement — and REFUSES to run
  unsandboxed if the sandbox is unimportable (empty corroboration);
* passes the shared strict read-only hardening flags from
  :func:`core.git.clone.safe_git_readonly_command` — the
  ``safe_git_command`` posture (fsmonitor / hooksPath / editor /
  pager / askpass / credential / gitProxy / gpg / diff.external
  neutralised) plus ``protocol.allow=never`` and
  ``core.sshCommand=false`` (this oracle is local-only; no transport
  should ever engage) and ``--no-pager``;
* uses list-based argv with the sanitised git env — never a shell
  string, never a repo path interpolated into a shell.

If the target is not a git repository or git is absent, the oracle
returns empty corroboration — never an error that disturbs the review
loop.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path

from core.git.clone import safe_git_readonly_command
from core.git.security_fixes import (
    GREP_UNION as _GREP_UNION,
)
from core.git.security_fixes import (
    SECURITY_FIX_PATTERNS,
    match_categories,
)
from core.run.scratch import scratch_dir

from ._util import safe_join

logger = logging.getLogger(__name__)

_GIT_TIMEOUT_S = 30
_MAX_COMMITS_DEFAULT = 8
_MAX_FILES_PER_COMMIT = 20
_CACHE_CAP = 256

# Namespace for anything this module stamps.  Deliberately NOT in
# evidence_grade.VALID_EVIDENCE_TOOLS / _TOOL_NAMESPACES — see module
# docstring.  test_git_oracle.py pins this invariant.
CORROBORATION_KIND = "git_history"

NOT_A_VERDICT_NOTE = (
    "corroboration only — prior security-fix history is context, "
    "never a confirmed/refuted verdict"
)

# Security-fix vocabulary — shared data owned by
# :mod:`core.git.security_fixes` ((regex, category) pairs; categories
# surface as ``matched_patterns`` on the records, the union regex
# feeds `git log --grep -i -E`).  ``SECURITY_FIX_PATTERNS`` is
# re-exported above for backwards compatibility; extend the shared
# module, not this one.

# Per-invocation hardening flags.  Env-level hygiene (get_safe_git_env)
# cannot suppress hostile per-repo .git/config — git reads it
# unconditionally — so hardening rides on every argv.  This module used
# to carry its own copy of the posture; it now consumes the shared
# strict read-only variant (single source of truth):
# ``core.git.clone.safe_git_readonly_command`` — the safe_git_command
# posture plus ``protocol.allow=never`` + ``core.sshCommand=false``
# (this oracle is local-only; no transport should ever engage) and
# ``--no-pager``.  Imported with the module's top-level imports.

_REC_SEP = "\x1e"
_FIELD_SEP = "\x1f"
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


# ---------------------------------------------------------------------------
# Result types (NOT SweepResult — no outcome, ever)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CorroborationRecord:
    """One prior security-relevant commit touching the finding's file."""

    sha: str
    subject: str
    date: str
    files: tuple = ()
    matched_patterns: tuple = ()
    touches_range: bool | None = None  # None = no line-range info

    def to_dict(self) -> dict:
        d: dict = {
            "sha": self.sha,
            "subject": self.subject,
            "date": self.date,
            "files": list(self.files),
            "matched_patterns": list(self.matched_patterns),
        }
        if self.touches_range is not None:
            d["touches_range"] = self.touches_range
        return d


@dataclass
class GitCorroboration:
    """Corroboration context for one finding.  Context, not verdict."""

    file_path: str
    records: list = field(default_factory=list)
    available: bool = True
    reason: str = ""

    def to_journal_dict(self) -> dict:
        """Journal / review-context payload.

        Carries an explicit not-a-verdict note and a ``kind`` that no
        evidence-grading path recognises as a tool stamp.
        """
        return {
            "kind": "corroboration",
            "source": CORROBORATION_KIND,
            "note": NOT_A_VERDICT_NOTE,
            "file": self.file_path,
            "records": [r.to_dict() for r in self.records],
        }


# ---------------------------------------------------------------------------
# Hardened, sandboxed git execution
# ---------------------------------------------------------------------------


def _git_env() -> dict | None:
    try:
        from core.git import get_safe_git_env
        return get_safe_git_env()
    except ImportError:
        return None


def _run_git(
    repo: Path,
    args: list,
    *,
    out_dir: Path | None = None,
) -> subprocess.CompletedProcess | None:
    """Run one hardened git command in the sandbox.

    Returns None when git is absent, the sandbox is unavailable
    (refuse-unsandboxed), or the invocation fails/times out.  Never
    raises.
    """
    git = shutil.which("git")
    if not git:
        return None

    try:
        from core.sandbox.context import run as sandbox_run
    except ImportError:
        # git parses hostile repo state — never run it unsandboxed.
        logger.debug(
            "git_oracle: core.sandbox unavailable — refusing to run git "
            "on an untrusted repo without isolation",
        )
        return None

    # Shared strict read-only posture; argv[0] swapped for the resolved
    # absolute git path (the helper emits a bare "git").
    cmd = safe_git_readonly_command("-C", str(repo), *args)
    cmd[0] = git
    with scratch_dir("git_oracle_", dir=out_dir) as workdir:
        try:
            return sandbox_run(
                cmd,
                block_network=True,
                target=str(repo),
                output=str(workdir),
                cwd=str(workdir),
                env=_git_env(),
                capture_output=True,
                text=True,
                timeout=_GIT_TIMEOUT_S,
                caller_label="audit-git-oracle",
            )
        except subprocess.TimeoutExpired:
            logger.debug("git_oracle: git timed out (%ss)", _GIT_TIMEOUT_S)
            return None
        except (subprocess.SubprocessError, OSError, ValueError,
                TypeError) as exc:
            logger.debug("git_oracle: git invocation failed: %s", exc)
            return None


def _is_git_repo(target_path: Path) -> bool:
    """Cheap structural check — a `.git` dir (clone) or file (worktree).

    Purely a stat; nothing from the repo is parsed or executed here.
    """
    return (Path(target_path) / ".git").exists()


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def _match_labels(subject: str, body: str) -> tuple:
    """Categories matching subject+body — thin shim over the shared
    classifier (kept because tests and parsers address it locally)."""
    return match_categories(f"{subject}\n{body}")


def _parse_log_records(stdout: str) -> list:
    """Parse `git log --format=%x1e%H%x1f%cI%x1f%s%x1f%b%x1f --name-only`."""
    records: list = []
    for chunk in (stdout or "").split(_REC_SEP):
        if not chunk.strip():
            continue
        fields = chunk.split(_FIELD_SEP)
        if len(fields) < 5:
            continue
        sha, date, subject, body, tail = fields[:5]
        sha = sha.strip()
        if not _SHA_RE.match(sha):
            continue
        files = tuple(
            ln.strip() for ln in tail.splitlines() if ln.strip()
        )[:_MAX_FILES_PER_COMMIT]
        records.append(CorroborationRecord(
            sha=sha,
            subject=subject.strip()[:300],
            date=date.strip(),
            files=files,
            matched_patterns=_match_labels(subject, body),
        ))
    return records


def _parse_sha_lines(stdout: str) -> set:
    """Extract full shas from output that may interleave diff content
    (``git log -L`` forces patch output on older git)."""
    return {
        ln.strip() for ln in (stdout or "").splitlines()
        if _SHA_RE.match(ln.strip())
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_CACHE_LOCK = threading.Lock()
_FILE_CACHE: dict = {}


def _reset_cache() -> None:
    """Test hook."""
    with _CACHE_LOCK:
        _FILE_CACHE.clear()


def corroborate_finding(
    *,
    target_path: Path,
    file_path: str,
    line_start: int = 0,
    line_end: int = 0,
    max_commits: int = _MAX_COMMITS_DEFAULT,
    out_dir: Path | None = None,
) -> GitCorroboration:
    """Query the local clone for prior security-fix history on a file.

    Args:
        target_path: Root of the (untrusted) target codebase.
        file_path: Finding's file, relative to the target root.
        line_start: Optional function start line.  When a valid range
            is given, each record is annotated with ``touches_range``
            (via ``git log -L``) — annotation only, records outside
            the range are still returned as file-level context.
        line_end: Optional function end line.
        max_commits: Cap on returned records.
        out_dir: Scratch/writable surface for the sandbox.

    Returns:
        GitCorroboration.  Empty (``records=[]``) with ``available=
        False`` when the target is not a git repo, git is absent, or
        the sandbox is unavailable — never an exception, never a
        verdict.
    """
    target_path = Path(target_path)

    if safe_join(target_path, file_path) is None:
        return GitCorroboration(
            file_path=file_path, available=False,
            reason=f"path escapes target: {file_path}",
        )
    if not _is_git_repo(target_path):
        return GitCorroboration(
            file_path=file_path, available=False,
            reason="not a git repository",
        )
    if not shutil.which("git"):
        return GitCorroboration(
            file_path=file_path, available=False,
            reason="git not installed",
        )

    rel = file_path.replace(os.sep, "/")
    cache_key = (str(target_path), rel, int(max_commits))
    with _CACHE_LOCK:
        cached = _FILE_CACHE.get(cache_key)

    if cached is None:
        proc = _run_git(
            target_path,
            [
                "log",
                "-n", str(int(max_commits)),
                "-i", "-E",
                f"--grep={_GREP_UNION}",
                "--date=iso-strict",
                (
                    f"--format={_REC_SEP}%H{_FIELD_SEP}%cI{_FIELD_SEP}%s"
                    f"{_FIELD_SEP}%b{_FIELD_SEP}"
                ),
                "--name-only",
                "--", rel,
            ],
            out_dir=out_dir,
        )
        if proc is None:
            return GitCorroboration(
                file_path=file_path, available=False,
                reason="git could not run (sandbox unavailable or "
                       "invocation failed)",
            )
        if proc.returncode != 0:
            logger.debug(
                "git_oracle: git log exited %d: %s",
                proc.returncode, (proc.stderr or "")[:200],
            )
            return GitCorroboration(
                file_path=file_path, available=False,
                reason=f"git log failed (exit {proc.returncode})",
            )
        cached = _parse_log_records(proc.stdout or "")
        with _CACHE_LOCK:
            if len(_FILE_CACHE) >= _CACHE_CAP:
                _FILE_CACHE.clear()
            _FILE_CACHE[cache_key] = cached

    records = list(cached)

    # Optional line-range annotation.  Best-effort: -L failures (older
    # git, renames) leave the file-level records unannotated.
    if records and line_start and line_end and 0 < line_start <= line_end:
        proc = _run_git(
            target_path,
            [
                "log",
                "--format=%H",
                # -L forces patch output — a diff-family invocation.
                # diff.external cannot be neutralised via -c (an empty
                # value is itself a configured command, see the
                # _SAFE_GIT_OVERRIDES comment in core.git.clone), so a
                # hostile repo-configured external diff driver is
                # closed off per-invocation here.
                "--no-ext-diff",
                "-L", f"{int(line_start)},{int(line_end)}:{rel}",
            ],
            out_dir=out_dir,
        )
        if proc is not None and proc.returncode == 0:
            in_range = _parse_sha_lines(proc.stdout or "")
            records = [
                CorroborationRecord(
                    sha=r.sha, subject=r.subject, date=r.date,
                    files=r.files, matched_patterns=r.matched_patterns,
                    touches_range=r.sha in in_range,
                )
                for r in records
            ]

    return GitCorroboration(file_path=file_path, records=records)


def corroboration_for_journal(
    *,
    target_path: Path,
    file_path: str,
    line_start: int = 0,
    line_end: int = 0,
    out_dir: Path | None = None,
) -> dict | None:
    """Journal-ready corroboration payload, or None when there is
    nothing to attach.  Never raises."""
    try:
        result = corroborate_finding(
            target_path=target_path,
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            out_dir=out_dir,
        )
    except Exception:
        logger.debug("git_oracle: corroboration failed", exc_info=True)
        return None
    if not result.records:
        return None
    return result.to_journal_dict()


# Explicit non-registration guard: importing evidence_grade here would
# be the only way to accidentally couple this module into the verdict
# path.  Keep the dependency direction one-way (tests import both and
# pin that is_tool_evidence(CORROBORATION_KIND) is False).
__all__ = [
    "CORROBORATION_KIND",
    "NOT_A_VERDICT_NOTE",
    "SECURITY_FIX_PATTERNS",
    "CorroborationRecord",
    "GitCorroboration",
    "corroborate_finding",
    "corroboration_for_journal",
]

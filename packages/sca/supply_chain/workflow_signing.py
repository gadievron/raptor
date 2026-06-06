"""Workflow-history signing-status check.

For each commit in the target repo that touched a GitHub Actions
workflow file (``.github/workflows/*.yml`` / ``.github/actions/**``
/ ``.github/dependabot.yml``), record the signature status.

Unsigned workflow commits are the entry vector for the Megalodon-
class attack (May 2026): an attacker with write access pushes a
forged-identity commit modifying workflow YAML, and the modified
workflow runs with the repo's secrets / OIDC tokens at the next
trigger.

Anomaly-shaped detection
~~~~~~~~~~~~~~~~~~~~~~~~

Many teams don't enforce universal commit signing — both because
not every developer has signing configured, and because GitHub's
"co-author" trailer can demote a fully-signed commit to "Partially
verified" if the co-author lacks a verified key. Flagging every
unsigned commit on such a repo would flood the report.

We instead compute the signing RATE across recent workflow-touching
commits and dispatch based on that:

  signing rate ≥ 70%  (norm is to sign)
    — Emit one finding PER unsigned commit at ``medium`` severity.
      These are anomalies against the established norm; an
      attacker pushing forged-identity commits would stand out.

  0% < signing rate < 70%  (norm is mixed)
    — Emit ONE hygiene finding at ``info`` severity describing the
      rate. Per-commit flagging would be noisy because the norm
      isn't to sign.

  signing rate == 0%  (no signing at all)
    — Emit ONE governance finding at ``info`` severity recommending
      ``git config commit.gpgsign true`` + the repo's branch-
      protection "Require signed commits" option.

The ``signed-ish`` count treats both ``G`` (verified) and ``U``
(partially-verified / untrusted-key) statuses as signed. This
matches GitHub's UI: both render as a "Verified" or "Partially
verified" badge — visible to a reviewer, and both raise the
attacker's bar above "no signing key needed." ``B`` / ``X`` /
``Y`` / ``R`` / ``E`` (problematic signature) statuses also
count as signed for rate purposes — they're not invisible
forgeries.

``%G?`` placeholder semantics (from git docs):
  G — good signature, key trusted in keyring
  U — good signature, key not in trusted keyring
  B — BAD signature (verification failed)
  X — good signature, key expired
  Y — good signature, expired key (note: distinct from X)
  R — good signature, revoked key
  E — cannot check (missing public key)
  N — no signature present

The detector is best-effort: returns no findings when the target
isn't a git repository, git binary is missing, or no workflow
files exist.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from ..models import Confidence, Dependency, Manifest, PinStyle

logger = logging.getLogger(__name__)

# Paths whose commit history we audit. Workflow YAML is the primary
# attack surface; composite-action definitions and ``dependabot.yml``
# also carry CI-executable content. Limited to .github/ — we don't
# audit every commit in the repo.
_AUDITED_PATHS = (
    ".github/workflows",
    ".github/actions",
    ".github/dependabot.yml",
    ".github/dependabot.yaml",
)

# Cap on the number of commits walked when computing the signing
# rate + per-commit findings. Tighter than the typical history-
# spanning audit because rate computation only needs a stable
# sample, not the full repo history. 100 covers most projects'
# CI evolution over 1-3 years.
_MAX_COMMITS_WALKED = 100

# Cap on the number of per-commit findings emitted (in the
# ``norm-is-to-sign`` branch). Avoids report explosion if a
# repo has 50+ unsigned anomalies — operator triages the most-
# recent ones; older ones are surfaced via the rate-summary
# finding.
_MAX_PER_COMMIT_FINDINGS = 20

# Threshold for "the team norm is to sign." Below this we emit
# a summary finding rather than per-commit anomalies. 0.7 picked
# empirically: real-world projects with strict signing policies
# tend to sit at 0.85-0.98 (commits from CI bots + a few co-
# authored merges drag the perfect-100% down). Projects without
# enforcement sit at 0.0-0.3 (only the few signing-aware
# committers contribute signed commits). 0.7 is a clean gap
# between those two clusters.
_NORM_RATE_THRESHOLD = 0.70

# Signature-status codes from ``git log --format=%G?`` that we
# count as "signed-ish" for rate purposes. Includes both G (fully
# verified) and U (partially verified / untrusted key) — both
# show as some flavour of "Verified" badge on GitHub and both
# raise the attacker's bar above a plain unsigned push.
#
# B / X / Y / R / E ARE also counted as signed for rate purposes —
# all mean "a signature is present, visible to a reviewer", which
# is meaningfully different from N (no signature at all = invisible
# to a reviewer scanning for badges).  This matches the top
# docstring intent.  Critically, E (missing-key-to-verify) is the
# default state for any signed commit in a freshly-cloned repo
# whose maintainers' keys aren't in the local trust store —
# raptor itself: every commit by the maintainer shows E in
# ``git log --format=%G?`` despite being verified on github.com.
# Treating E as unsigned would FP-flood every clone-time scan.
#
# Only N (no signature present) is treated as unsigned.
_SIGNED_STATUSES = frozenset(("G", "U", "B", "X", "Y", "R", "E"))


@dataclass(frozen=True)
class WorkflowUnsignedCommit:
    """One commit in the workflow-file history without a
    signature. Emitted only in the ``norm-is-to-sign`` branch where
    individual unsigned commits are anomalies."""

    commit_sha: str
    sig_status: str            # always "N" for emitted findings
    author_name: str
    author_email: str
    subject: str               # commit message first line


@dataclass(frozen=True)
class WorkflowSigningStats:
    """Aggregate signing rate over the recent workflow-touching
    commits. Used to emit a summary finding in the mixed-or-
    unsigned regimes."""

    commits_walked: int
    signed_count: int
    unsigned_count: int
    signing_rate: float        # signed_count / commits_walked


@dataclass(frozen=True)
class WorkflowSigningFinding:
    """Internal carrier; the orchestrator picks ``kind`` based on
    whether ``unsigned_commit`` or ``stats`` is populated."""

    dependency: Dependency
    severity: str
    confidence: Confidence
    unsigned_commit: Optional[WorkflowUnsignedCommit] = None
    stats: Optional[WorkflowSigningStats] = None


def scan_target(
    target: Path, manifests: List[Manifest],
) -> List[WorkflowSigningFinding]:
    """Walk recent workflow-file history; dispatch by signing rate.

    ``manifests`` is accepted for orchestrator-side symmetry; not
    used directly (the audit is git-log-driven, not manifest-
    driven).
    """
    if not _is_git_repo(target):
        return []
    if shutil.which("git") is None:
        return []
    if not any((target / p).exists() for p in _AUDITED_PATHS):
        return []
    walked = _git_log_signatures(target, _AUDITED_PATHS)
    if not walked:
        return []
    signed = sum(1 for entry in walked if entry[1] in _SIGNED_STATUSES)
    total = len(walked)
    unsigned = total - signed
    rate = signed / total if total else 0.0
    stats = WorkflowSigningStats(
        commits_walked=total, signed_count=signed,
        unsigned_count=unsigned, signing_rate=rate,
    )
    host = _placeholder_host(target)

    if rate >= _NORM_RATE_THRESHOLD and unsigned > 0:
        # Norm is to sign — flag individual unsigned commits as
        # anomalies. Anomalous unsigned commits in a signing-norm
        # repo are the Megalodon-attack signature.
        return _per_commit_anomaly_findings(walked, host)

    # Either no unsigned commits (perfect signing) or norm is
    # mixed-or-unsigned. Emit a single summary finding.
    if unsigned == 0:
        return []  # 100% signed — no signal to surface
    return [_summary_finding(stats, host)]


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _is_git_repo(target: Path) -> bool:
    # ``.git`` may be a directory (regular repo) or a file
    # (worktrees, submodules) — both indicate a git repo.
    return (target / ".git").exists()


def _git_log_signatures(
    target: Path, paths: tuple,
) -> List[tuple]:
    """Return ``[(sha, sig_status, author_name, author_email, subject), ...]``
    for the most-recent ``_MAX_COMMITS_WALKED`` commits touching
    ``paths``. Empty list on any git failure."""
    cmd = [
        "git", "-C", str(target), "log",
        f"--max-count={_MAX_COMMITS_WALKED}",
        "--no-merges",
        "--format=%H|%G?|%an|%ae|%s",
        "--",
    ]
    cmd.extend(paths)
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        logger.debug(
            "sca.supply_chain.workflow_signing: git log failed: %s", e,
        )
        return []
    if proc.returncode != 0:
        logger.debug(
            "sca.supply_chain.workflow_signing: git log exit=%d stderr=%r",
            proc.returncode, proc.stderr,
        )
        return []
    out: List[tuple] = []
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split("|", 4)
        if len(parts) < 5:
            continue
        out.append(tuple(parts))
    return out


def _per_commit_anomaly_findings(
    walked: List[tuple], host: Dependency,
) -> List[WorkflowSigningFinding]:
    """Norm-is-to-sign branch: emit one finding per unsigned commit
    in the walked window, capped at ``_MAX_PER_COMMIT_FINDINGS``."""
    out: List[WorkflowSigningFinding] = []
    for entry in walked:
        sha, sig_status, author_name, author_email, subject = entry
        if sig_status != "N":
            continue
        if len(out) >= _MAX_PER_COMMIT_FINDINGS:
            break
        out.append(WorkflowSigningFinding(
            dependency=host,
            severity="medium",
            confidence=Confidence(
                "high",
                reason=(
                    "unsigned commit anomalous against repo's "
                    "signing norm"
                ),
            ),
            unsigned_commit=WorkflowUnsignedCommit(
                commit_sha=sha,
                sig_status=sig_status,
                author_name=author_name,
                author_email=author_email,
                subject=subject,
            ),
        ))
    return out


def _summary_finding(
    stats: WorkflowSigningStats, host: Dependency,
) -> WorkflowSigningFinding:
    """Mixed-or-unsigned-norm branch: emit ONE hygiene finding.
    Severity is ``info`` — operator awareness, not actionable
    per-commit."""
    return WorkflowSigningFinding(
        dependency=host,
        severity="info",
        confidence=Confidence(
            "high",
            reason="git log signing-rate aggregate",
        ),
        stats=stats,
    )


def _placeholder_host(target: Path) -> Dependency:
    """Findings need a Dependency to attach to. Workflow-signing
    findings don't naturally bind to a single package — they're
    repo-level governance. We synthesise a placeholder rooted at
    the target's ``.github/`` directory so the report has
    a coherent declared_in path."""
    return Dependency(
        ecosystem="GitHub Actions",
        name="<workflow-history>",
        version=None,
        declared_in=target / ".github",
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.UNKNOWN,
        direct=True,
        purl="",
        parser_confidence=Confidence(
            "low",
            reason="placeholder for workflow-signing finding host",
        ),
    )


__all__ = [
    "WorkflowSigningFinding",
    "WorkflowSigningStats",
    "WorkflowUnsignedCommit",
    "scan_target",
]

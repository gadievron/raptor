"""Commit-provenance discrepancy detector (Phase 7).

For each commit in the target repo that touched a dependency
manifest in the last ``_MAX_COMMITS_WALKED`` commits, check whether
the claimed identity is internally consistent with the signature
status and the timestamp shape.

The d-PPE / identity-forgery attack class — distinct from the
``workflow_signing`` posture check — produces commits that:

  * Claim a bot/automation identity in the author field
    (``dependabot[bot]``, ``renovate[bot]``, ``github-actions[bot]``,
    etc.) — to slip past human reviewers who'd scrutinise a
    contributor name
  * Lack a verified signature (most real bots DO sign their commits
    via the GitHub-hosted Apps API, so an unsigned bot-identity
    commit is itself anomalous)
  * Show an unusual author/committer date skew — the attacker
    typically rebases or backdates the forged commit

The conjunction is the actionable signal.  Any one alone is too
noisy (signing is optional in many repos; bots without signatures
do exist; date skew on rebases is normal).

# Adversarial model

What this detector must defend against:

  * **Bot-identity vocabulary drift** — new automation accounts
    appear regularly.  Defence: prefix-match the canonical
    ``*[bot]`` suffix in author name OR known bot emails; the
    suffix convention is GitHub-enforced.
  * **Repos that don't sign anything** — a 0%-signing repo would
    produce a finding on every bot commit.  Defence: combine with
    date-skew.  A bot commit on a 0%-signing repo with normal
    timestamps gets no finding; the date-skew piece raises the
    bar.
  * **Rebase legitimately skews timestamps** — yes, but the skew
    is bounded by when the rebase happened.  A skew > 90 days
    (default) is anomalous because it implies the work claims to
    originate from much earlier than the actual commit moment.
  * **Operator running the scan on a shallow clone** — git log
    only sees what's in the clone.  Best-effort; documented.

# Soundness invariant

A finding here means: "this commit claims an automation identity,
lacks a verified signature, AND has anomalous author/committer date
skew".  It does NOT prove forgery — it surfaces the conjunction
for human review.
"""

from __future__ import annotations

import logging
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Optional, Sequence

from ..models import Confidence, Dependency, Manifest, PinStyle

logger = logging.getLogger(__name__)


# Manifest filenames whose commit history we audit.  Limited to
# directly-dependency-bearing manifests + lockfiles; auxiliary
# files (READMEs, configs) are out of scope.
_MANIFEST_FILENAMES = frozenset({
    # npm / yarn / pnpm
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    # PyPI
    "requirements.txt", "requirements.in", "requirements-dev.txt",
    "Pipfile", "Pipfile.lock",
    "pyproject.toml", "poetry.lock", "uv.lock",
    "setup.py", "setup.cfg",
    # Cargo
    "Cargo.toml", "Cargo.lock",
    # Composer
    "composer.json", "composer.lock",
    # RubyGems
    "Gemfile", "Gemfile.lock",
    # Go
    "go.mod", "go.sum",
    # GitHub Actions
    # (omitted — covered by ``workflow_signing`` already)
})


# Bot-identity author-email suffixes used by common automation
# services.  Author name ``foo[bot]`` also counts.
_BOT_EMAIL_SUFFIXES = (
    "@users.noreply.github.com",     # default for GitHub-hosted bots
    "@dependabot.com",
    "@renovate.com",
    "@whitesourcesoftware.com",
    "@mend.io",
    "@snyk.io",
    "@github.com",                   # noreply@github.com
)


_BOT_NAME_MARKERS = (
    "[bot]",                          # GitHub convention
    "dependabot", "renovate",
    "github-actions",
    "snyk-bot", "mend-bot",
    "imgbot", "allcontributors[bot]",
)


# Canonical-email patterns for the major automation accounts.  A
# real ``dependabot[bot]`` commit has email
# ``49699333+dependabot[bot]@users.noreply.github.com`` — the
# numeric prefix is the bot's stable GitHub user ID and is the
# discriminator between a legitimate rebased bot commit and an
# attacker who has set git config to CLAIM the bot name.
#
# FP-tightening: when the author NAME matches a bot marker AND the
# email matches the canonical pattern, we treat the conjunction as
# a real (rebased) bot commit and SUPPRESS the finding even though
# the bot+unsigned+skewed-date shape would otherwise fire.  The
# legitimate-but-skewed shape is dependabot's normal rebase
# behaviour; flagging it would FP-flood every active repo.
#
# An attacker who can ALSO match the canonical email pattern has
# either compromised the bot's account (out of scope — that's
# upstream) or has write access to the repo with the ability to
# set canonical author identity (still high blast radius, but
# the email-mismatch path catches the lower-bar shape).
_CANONICAL_BOT_EMAIL_RE = re.compile(
    r"^\d+\+"
    r"(?:dependabot|renovate|github-actions|snyk-bot|mend-bot|imgbot)"
    r"\[bot\]"
    r"@users\.noreply\.github\.com$",
    re.IGNORECASE,
)


_DEFAULT_MAX_COMMITS_WALKED = 100
# Author/committer date skew threshold.  Bots normally commit with
# author_date ≈ committer_date (within hours).  90 days catches
# rebases of pre-existing work + clock-skewed forgeries while
# tolerating normal release-branch churn.
_DEFAULT_DATE_SKEW_DAYS = 90
# Signature statuses that count as "not signed" (worth flagging).
# Mirrors :data:`workflow_signing._SIGNED_STATUSES`.
_UNSIGNED_STATUSES = frozenset({"N", "E"})


@dataclass(frozen=True)
class CommitProvenanceHit:
    """One commit whose provenance is anomalous."""

    commit_sha: str
    sig_status: str
    author_name: str
    author_email: str
    author_date_iso: str
    committer_date_iso: str
    skew_days: int
    subject: str
    paths_touched: List[str]


@dataclass(frozen=True)
class CommitProvenanceFinding:
    dependency: Dependency
    hit: CommitProvenanceHit
    severity: str
    confidence: Confidence


def scan_target(
    target: Path,
    manifests: Sequence[Manifest] = (),
    deps: Sequence[Dependency] = (),
    *,
    max_commits: int = _DEFAULT_MAX_COMMITS_WALKED,
    date_skew_days: int = _DEFAULT_DATE_SKEW_DAYS,
) -> List[CommitProvenanceFinding]:
    """Walk the manifest-touching commit history of ``target`` and
    emit findings on bot-identity-claim + unsigned + skewed-dates
    conjunctions.

    Returns empty list on any git failure (not a repo, git missing,
    shallow clone with no history, etc.).
    """
    target = target.resolve()
    if not (target / ".git").exists():
        return []
    manifest_paths = _resolve_manifest_paths(target, manifests)
    if not manifest_paths:
        return []
    rows = _git_log_provenance(target, manifest_paths, max_commits)
    if not rows:
        return []
    host = _placeholder_dep(target)
    out: List[CommitProvenanceFinding] = []
    for row in rows:
        finding = _classify(row, host, date_skew_days)
        if finding is not None:
            out.append(finding)
    return out


def _classify(
    row: dict, host: Dependency, date_skew_days: int,
) -> Optional[CommitProvenanceFinding]:
    """Apply the three-way conjunction.  Returns None when the
    commit doesn't earn a finding."""
    sig_status = row["sig_status"]
    author_name = row["author_name"]
    author_email = row["author_email"]

    if sig_status not in _UNSIGNED_STATUSES:
        return None
    bot_claim = _classify_bot_claim(author_name, author_email)
    if bot_claim == "none":
        return None
    if bot_claim == "canonical":
        # Real rebased bot commit — author email matches the
        # canonical ``<numeric-id>+<bot>[bot]@users.noreply.github.com``
        # shape.  Skewed dates are dependabot's normal rebase
        # behaviour; firing here would FP-flood every active repo.
        return None
    skew = _date_skew_days(row["author_date_iso"], row["committer_date_iso"])
    if skew is None or skew < date_skew_days:
        return None
    hit = CommitProvenanceHit(
        commit_sha=row["sha"],
        sig_status=sig_status,
        author_name=author_name,
        author_email=author_email,
        author_date_iso=row["author_date_iso"],
        committer_date_iso=row["committer_date_iso"],
        skew_days=skew,
        subject=row["subject"],
        paths_touched=row.get("paths_touched", []),
    )
    return CommitProvenanceFinding(
        dependency=host,
        hit=hit,
        severity="high",
        confidence=Confidence(
            "medium",
            reason=(
                "bot-identity author + unsigned + author/committer "
                f"date skew {skew}d (forgery-shape conjunction)"
            ),
        ),
    )


def _classify_bot_claim(name: str, email: str) -> str:
    """Classify the bot-identity claim shape.

    Returns one of:
      * ``"none"`` — no automation identity claimed
      * ``"canonical"`` — bot identity claimed AND email matches
        the canonical ``<numeric-id>+<bot>[bot]@users.noreply.github.com``
        pattern.  Treated as a legitimate rebased bot commit and
        suppressed in :func:`_classify`.
      * ``"impersonation"`` — bot identity claimed in the AUTHOR
        NAME but email does NOT match the canonical pattern.  This
        is the actual forgery signal — anyone with write access to
        the repo can ``git config user.name "dependabot[bot]"`` and
        push, but they can't produce the canonical email shape
        without controlling the real bot account.
    """
    lname = (name or "").lower()
    lemail = (email or "").lower()
    claims_bot = False
    for marker in _BOT_NAME_MARKERS:
        if marker in lname:
            claims_bot = True
            break
    if not claims_bot:
        for suffix in _BOT_EMAIL_SUFFIXES:
            if not lemail.endswith(suffix):
                continue
            if suffix == "@users.noreply.github.com":
                local = lemail.split("@", 1)[0]
                if "bot" in local or "actions" in local:
                    claims_bot = True
                    break
                continue
            claims_bot = True
            break
    if not claims_bot:
        return "none"
    if _CANONICAL_BOT_EMAIL_RE.match(lemail):
        return "canonical"
    return "impersonation"


def _date_skew_days(author_iso: str, committer_iso: str) -> Optional[int]:
    """Return absolute skew (days) between author and committer
    timestamps.  None when either timestamp fails to parse."""
    a = _parse_iso(author_iso)
    c = _parse_iso(committer_iso)
    if a is None or c is None:
        return None
    return abs((c - a).days)


def _parse_iso(iso: str) -> Optional[datetime]:
    """Parse git's ``--date=iso-strict`` output.  Returns timezone-
    aware datetime or None on failure."""
    iso = iso.strip()
    if not iso:
        return None
    try:
        # ``fromisoformat`` accepts the ``+00:00`` form git emits.
        return datetime.fromisoformat(iso).astimezone(timezone.utc)
    except ValueError:
        return None


def _resolve_manifest_paths(
    target: Path, manifests: Sequence[Manifest],
) -> List[str]:
    """Return repo-relative paths of every manifest under ``target``
    matching ``_MANIFEST_FILENAMES``.  When ``manifests`` is supplied,
    use it; otherwise walk the tree for any matching file.
    """
    paths: List[str] = []
    if manifests:
        for m in manifests:
            if m.path.name not in _MANIFEST_FILENAMES:
                continue
            try:
                rel = m.path.resolve().relative_to(target)
            except ValueError:
                continue
            paths.append(str(rel))
        if paths:
            return paths
    # Fallback walk — bounded; only top-level + immediate subdirs.
    for entry in _iter_manifest_files(target):
        try:
            rel = entry.resolve().relative_to(target)
        except ValueError:
            continue
        paths.append(str(rel))
    return paths


def _iter_manifest_files(target: Path) -> Iterable[Path]:
    """Bounded walk for manifest files when the caller hasn't passed
    a manifest list.  Honours the ``EXCLUDED_DIR_NAMES`` skip set."""
    import os
    from ..discovery import EXCLUDED_DIR_NAMES
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIR_NAMES]
        for fn in filenames:
            if fn in _MANIFEST_FILENAMES:
                yield Path(dirpath) / fn


def _git_log_provenance(
    target: Path, paths: List[str], max_commits: int,
) -> List[dict]:
    """Run ``git log`` over ``paths`` and parse provenance fields.

    Output format: ``%H|%G?|%an|%ae|%aI|%cI|%s`` per commit, then
    ``git log --name-only`` interleaves the touched paths.
    We use a NUL-separated record format so subject lines with ``|``
    don't break the parser.
    """
    # Use NUL between fields + form-feed between records so embedded
    # ``|`` in subjects doesn't break parsing.
    fmt = "%H%x00%G?%x00%an%x00%ae%x00%aI%x00%cI%x00%s%x00%x0c"
    cmd = [
        "git", "-C", str(target), "log",
        f"--max-count={max_commits}",
        "--no-merges",
        f"--format={fmt}",
        "--name-only",
        "--",
    ]
    cmd.extend(paths)
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        logger.debug(
            "sca.supply_chain.commit_provenance: git log failed: %s", e,
        )
        return []
    if proc.returncode != 0:
        logger.debug(
            "sca.supply_chain.commit_provenance: git log exit=%d stderr=%r",
            proc.returncode, proc.stderr,
        )
        return []
    return _parse_git_log(proc.stdout)


def _parse_git_log(stdout: str) -> List[dict]:
    """Parse the NUL/FF-delimited git log stream into row dicts."""
    out: List[dict] = []
    for record in stdout.split("\x0c"):
        record = record.strip("\n")
        if not record:
            continue
        # The first 7 NUL-delimited fields are the header; the rest
        # (newline-separated) are the touched paths.
        parts = record.split("\x00")
        if len(parts) < 8:
            continue
        sha, sig, an, ae, ai, ci, subj = parts[:7]
        tail = "\x00".join(parts[7:])
        paths_touched = [p for p in tail.splitlines() if p.strip()]
        out.append({
            "sha": sha,
            "sig_status": sig,
            "author_name": an,
            "author_email": ae,
            "author_date_iso": ai,
            "committer_date_iso": ci,
            "subject": subj,
            "paths_touched": paths_touched,
        })
    return out


def _placeholder_dep(target: Path) -> Dependency:
    """Findings here describe repo-level posture; attribute to a
    placeholder dep so the orchestrator's normal carrier semantics
    apply."""
    return Dependency(
        ecosystem="<repo>",
        name="<commit-history>",
        version=None,
        declared_in=target,
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.UNKNOWN,
        direct=True,
        purl="",
        parser_confidence=Confidence(
            "low", reason="placeholder for commit-provenance finding host",
        ),
    )


__all__ = [
    "CommitProvenanceFinding",
    "CommitProvenanceHit",
    "scan_target",
]

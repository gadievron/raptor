"""Tests for the ``commit_provenance`` detector (Phase 7).

The detector flags commits touching dependency manifests when ALL
FOUR hold:
  1. Author NAME claims a bot/automation identity
  2. Author EMAIL does NOT match the canonical-bot pattern
     (``<numeric-id>+<bot>[bot]@users.noreply.github.com``)
  3. Signature status is ``N`` (unsigned) or ``E`` (unverifiable)
  4. Author/committer date skew exceeds the threshold (default 90d)

Suppression: when leg 1 holds AND leg 2 holds in the CANONICAL
direction (canonical email DOES match), we treat the commit as a
legitimate rebased bot commit (dependabot's normal behaviour) and
suppress the finding.  Only the impersonation shape — bot name
claimed without canonical email — earns a finding.

Tests use real local git repos created via subprocess — the
detector is git-log-driven so this exercises the actual code path.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from packages.sca.supply_chain import commit_provenance


def _have_git() -> bool:
    """Check git is on PATH so we skip cleanly in environments
    that lack it (CI minimal images, etc.)."""
    try:
        proc = subprocess.run(
            ["git", "--version"], capture_output=True, timeout=5,
        )
        return proc.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


_GIT_AVAILABLE = _have_git()
pytestmark = pytest.mark.skipif(
    not _GIT_AVAILABLE, reason="git binary not available",
)


def _init_repo(tmp_path: Path) -> None:
    subprocess.run(
        ["git", "init", "-q", "--initial-branch=main", str(tmp_path)],
        check=True, capture_output=True,
    )
    # Disable signing globally for these tests — we want explicit
    # control over signature status.
    for key, val in (
        ("commit.gpgsign", "false"),
        ("tag.gpgsign", "false"),
        ("user.name", "Test"),
        ("user.email", "test@example.com"),
    ):
        subprocess.run(
            ["git", "-C", str(tmp_path), "config", key, val],
            check=True, capture_output=True,
        )


def _commit(
    tmp_path: Path,
    *,
    filename: str,
    content: str,
    author_name: str = "Test",
    author_email: str = "test@example.com",
    author_date: str = "2026-06-01T12:00:00+00:00",
    commit_date: str = "2026-06-01T12:00:00+00:00",
) -> str:
    """Create a single commit with explicit author + commit dates;
    return its full SHA."""
    (tmp_path / filename).write_text(content, encoding="utf-8")
    subprocess.run(
        ["git", "-C", str(tmp_path), "add", filename],
        check=True, capture_output=True,
    )
    env = os.environ.copy()
    env["GIT_AUTHOR_NAME"] = author_name
    env["GIT_AUTHOR_EMAIL"] = author_email
    env["GIT_AUTHOR_DATE"] = author_date
    env["GIT_COMMITTER_NAME"] = author_name
    env["GIT_COMMITTER_EMAIL"] = author_email
    env["GIT_COMMITTER_DATE"] = commit_date
    subprocess.run(
        ["git", "-C", str(tmp_path), "commit",
         "-q", "-m", f"chore: update {filename}"],
        check=True, capture_output=True, env=env,
    )
    proc = subprocess.run(
        ["git", "-C", str(tmp_path), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    )
    return proc.stdout.strip()


# ---------------------------------------------------------------------------
# Positive cases — conjunction fires
# ---------------------------------------------------------------------------

def test_canonical_dependabot_email_does_not_fire(tmp_path: Path) -> None:
    """A real dependabot rebase has the canonical email shape AND
    will commonly show 100+ day skew — the legitimate-but-skewed
    state.  Must NOT fire (FP suppression)."""
    _init_repo(tmp_path)
    _commit(
        tmp_path, filename="package.json", content='{"name": "x"}',
        author_name="dependabot[bot]",
        author_email="49699333+dependabot[bot]@users.noreply.github.com",
        author_date="2026-01-01T00:00:00+00:00",
        commit_date="2026-06-01T00:00:00+00:00",   # 151 days later
    )
    hits = commit_provenance.scan_target(tmp_path)
    assert hits == []


def test_bot_name_with_non_canonical_email_fires(tmp_path: Path) -> None:
    """Author claims ``dependabot[bot]`` but email is a self-hosted
    address (no canonical noreply pattern, no numeric prefix).
    THIS is the actual forgery shape and must fire."""
    _init_repo(tmp_path)
    _commit(
        tmp_path, filename="package.json", content='{"name": "x"}',
        author_name="dependabot[bot]",
        author_email="attacker@example.com",
        author_date="2026-01-01T00:00:00+00:00",
        commit_date="2026-06-01T00:00:00+00:00",
    )
    hits = commit_provenance.scan_target(tmp_path)
    assert len(hits) == 1
    assert hits[0].severity == "high"
    assert hits[0].hit.skew_days >= 90


def test_bot_name_with_noreply_but_no_numeric_prefix_fires(
    tmp_path: Path,
) -> None:
    """Email at ``@users.noreply.github.com`` BUT without the
    numeric-id prefix that real bot accounts have — forgery shape."""
    _init_repo(tmp_path)
    _commit(
        tmp_path, filename="package.json", content='{"name": "y"}',
        author_name="renovate[bot]",
        author_email="renovate[bot]@users.noreply.github.com",
        author_date="2026-01-01T00:00:00+00:00",
        commit_date="2026-06-01T00:00:00+00:00",
    )
    hits = commit_provenance.scan_target(tmp_path)
    assert hits


def test_canonical_renovate_email_suppressed(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    _commit(
        tmp_path, filename="package.json", content='{"name": "y"}',
        author_name="renovate[bot]",
        author_email="29139614+renovate[bot]@users.noreply.github.com",
        author_date="2026-01-01T00:00:00+00:00",
        commit_date="2026-06-01T00:00:00+00:00",
    )
    hits = commit_provenance.scan_target(tmp_path)
    assert hits == []


def test_canonical_github_actions_email_suppressed(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    _commit(
        tmp_path, filename="requirements.txt", content="flask==2.0\n",
        author_name="github-actions[bot]",
        author_email="41898282+github-actions[bot]"
                     "@users.noreply.github.com",
        author_date="2026-01-01T00:00:00+00:00",
        commit_date="2026-06-01T00:00:00+00:00",
    )
    hits = commit_provenance.scan_target(tmp_path)
    assert hits == []


# ---------------------------------------------------------------------------
# Negative cases — each individual leg alone insufficient
# ---------------------------------------------------------------------------

def test_human_author_no_finding(tmp_path: Path) -> None:
    """Unsigned + skewed dates but HUMAN identity — no finding."""
    _init_repo(tmp_path)
    _commit(
        tmp_path, filename="package.json", content='{"name": "z"}',
        author_name="Alice Smith", author_email="alice@example.com",
        author_date="2026-01-01T00:00:00+00:00",
        commit_date="2026-06-01T00:00:00+00:00",
    )
    hits = commit_provenance.scan_target(tmp_path)
    assert hits == []


def test_bot_with_small_skew_no_finding(tmp_path: Path) -> None:
    """Bot + unsigned but skew under threshold — no finding."""
    _init_repo(tmp_path)
    _commit(
        tmp_path, filename="package.json", content='{"name": "w"}',
        author_name="dependabot[bot]",
        author_email="49699333+dependabot[bot]@users.noreply.github.com",
        author_date="2026-06-01T00:00:00+00:00",
        commit_date="2026-06-01T08:00:00+00:00",  # 8 hours, 0 days
    )
    hits = commit_provenance.scan_target(tmp_path)
    assert hits == []


def test_non_manifest_path_ignored(tmp_path: Path) -> None:
    """A commit touching ONLY non-manifest files (README, src/) must
    not be checked, even with all three legs of the conjunction."""
    _init_repo(tmp_path)
    _commit(
        tmp_path, filename="README.md", content="hello\n",
        author_name="dependabot[bot]",
        author_email="49699333+dependabot[bot]@users.noreply.github.com",
        author_date="2026-01-01T00:00:00+00:00",
        commit_date="2026-06-01T00:00:00+00:00",
    )
    hits = commit_provenance.scan_target(tmp_path)
    assert hits == []


def test_not_a_git_repo_returns_empty(tmp_path: Path) -> None:
    """No .git dir → graceful empty result."""
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    assert commit_provenance.scan_target(tmp_path) == []


# ---------------------------------------------------------------------------
# Multi-commit / mixed history
# ---------------------------------------------------------------------------

def test_mixed_history_only_impersonation_fires(tmp_path: Path) -> None:
    """A repo with 1 IMPERSONATION-shape commit and 1 normal commit
    should emit ONE finding (the impersonation only).  Canonical-
    email bot commits and human commits are both suppressed."""
    _init_repo(tmp_path)
    _commit(
        tmp_path, filename="requirements.txt", content="a==1\n",
        author_name="Alice", author_email="alice@example.com",
        author_date="2026-05-01T00:00:00+00:00",
        commit_date="2026-05-01T00:00:00+00:00",
    )
    _commit(
        tmp_path, filename="requirements.txt", content="a==1\nb==1\n",
        author_name="dependabot[bot]",
        author_email="attacker@evil.example",
        author_date="2025-08-01T00:00:00+00:00",
        commit_date="2026-06-01T00:00:00+00:00",  # ~304 days
    )
    hits = commit_provenance.scan_target(tmp_path)
    assert len(hits) == 1
    assert "dependabot" in hits[0].hit.author_name
    assert hits[0].hit.author_email == "attacker@evil.example"


def test_custom_threshold_overrides_default(tmp_path: Path) -> None:
    """Operator can pass a tighter ``date_skew_days`` to surface
    smaller anomalies.  Uses impersonation-shape email so the
    canonical-suppression path doesn't apply."""
    _init_repo(tmp_path)
    _commit(
        tmp_path, filename="package.json", content="{}",
        author_name="dependabot[bot]",
        author_email="attacker@evil.example",
        author_date="2026-06-01T00:00:00+00:00",
        commit_date="2026-06-15T00:00:00+00:00",  # 14 days
    )
    # Default threshold of 90 days → no finding.
    assert commit_provenance.scan_target(tmp_path) == []
    # Tightened to 7 days → finding.
    hits = commit_provenance.scan_target(tmp_path, date_skew_days=7)
    assert hits and hits[0].hit.skew_days == 14

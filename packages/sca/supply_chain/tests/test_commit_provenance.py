"""Tests for the ``commit_provenance`` detector (Phase 7).

The detector flags commits touching dependency manifests when ALL
THREE hold:
  1. Author identity claims a bot/automation identity
  2. Signature status is ``N`` (unsigned) or ``E`` (unverifiable)
  3. Author/committer date skew exceeds the threshold (default 90d)

The author EMAIL then splits the finding into two shapes, both
emitted (downgrade, never suppress):
  * email does NOT match the canonical-bot pattern
    (``<numeric-id>+<bot>[bot]@users.noreply.github.com``) —
    the low-effort forgery shape, high severity
  * email DOES match the canonical pattern — usually a legitimate
    rebased bot commit, but the email is unauthenticated free text
    on an unsigned commit, so the finding stays visible at reduced
    severity/confidence for provenance review

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
            check=False,
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

def test_canonical_dependabot_email_downgrades(tmp_path: Path) -> None:
    """A real dependabot rebase has the canonical email shape AND
    will commonly show 100+ day skew — the legitimate-but-skewed
    state. The author email is free text, so on an unsigned commit
    the canonical shape can't justify suppression; the conjunction
    still surfaces, at reduced severity/confidence."""
    _init_repo(tmp_path)
    _commit(
        tmp_path, filename="package.json", content='{"name": "x"}',
        author_name="dependabot[bot]",
        author_email="49699333+dependabot[bot]@users.noreply.github.com",
        author_date="2026-01-01T00:00:00+00:00",
        commit_date="2026-06-01T00:00:00+00:00",   # 151 days later
    )
    hits = commit_provenance.scan_target(tmp_path)
    assert len(hits) == 1
    assert hits[0].severity == "medium"
    assert hits[0].confidence.level == "low"


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


def test_canonical_renovate_email_downgrades(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    _commit(
        tmp_path, filename="package.json", content='{"name": "y"}',
        author_name="renovate[bot]",
        author_email="29139614+renovate[bot]@users.noreply.github.com",
        author_date="2026-01-01T00:00:00+00:00",
        commit_date="2026-06-01T00:00:00+00:00",
    )
    hits = commit_provenance.scan_target(tmp_path)
    assert [(h.severity, h.confidence.level) for h in hits] == [
        ("medium", "low"),
    ]


def test_canonical_github_actions_email_downgrades(tmp_path: Path) -> None:
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
    assert [(h.severity, h.confidence.level) for h in hits] == [
        ("medium", "low"),
    ]


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
    should emit ONE finding (the impersonation only).  Human commits
    never earn a finding."""
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
    full-severity path is exercised."""
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


# ---------------------------------------------------------------------------
# Signed path unchanged + downgraded-finding labelling
# ---------------------------------------------------------------------------

def _row(sig_status: str, email: str, name: str = "dependabot[bot]") -> dict:
    return {
        "sha": "a" * 40,
        "sig_status": sig_status,
        "author_name": name,
        "author_email": email,
        "author_date_iso": "2026-01-01T00:00:00+00:00",
        "committer_date_iso": "2026-06-01T00:00:00+00:00",  # 151d skew
        "subject": "chore: bump deps",
        "paths_touched": ["package.json"],
    }


_CANONICAL_EMAIL = "49699333+dependabot[bot]@users.noreply.github.com"


def test_signed_bot_commit_earns_no_finding(tmp_path: Path) -> None:
    """Signed (G/U) bot commits are out of scope regardless of email
    shape — the signature IS the authenticated identity."""
    host = commit_provenance._placeholder_dep(tmp_path)
    for sig in ("G", "U"):
        for email in (_CANONICAL_EMAIL, "attacker@evil.example"):
            assert commit_provenance._classify(
                _row(sig, email), host, 90,
            ) is None


def test_unsigned_canonical_email_is_downgraded_not_suppressed(
    tmp_path: Path,
) -> None:
    """Unsigned + canonical bot email → a finding is still emitted,
    at reduced severity/confidence, tagged with the canonical claim
    shape."""
    host = commit_provenance._placeholder_dep(tmp_path)
    finding = commit_provenance._classify(_row("N", _CANONICAL_EMAIL), host, 90)
    assert finding is not None
    assert finding.severity == "medium"
    assert finding.confidence.level == "low"
    assert finding.claim_shape == "canonical"


def test_downgraded_finding_is_clearly_labelled(tmp_path: Path) -> None:
    """The SupplyChainFinding rendered from the downgraded shape names
    the trusted-bot-email situation and tells the reviewer to verify
    provenance — visibly different from the impersonation label."""
    from packages.sca.supply_chain import _commit_provenance_to_finding

    host = commit_provenance._placeholder_dep(tmp_path)
    canonical = commit_provenance._classify(
        _row("N", _CANONICAL_EMAIL), host, 90,
    )
    impersonation = commit_provenance._classify(
        _row("N", "attacker@evil.example"), host, 90,
    )
    scf_canonical = _commit_provenance_to_finding(canonical)
    scf_impersonation = _commit_provenance_to_finding(impersonation)

    assert "impersonation" in scf_canonical.detail
    assert "verify provenance" in scf_canonical.detail
    assert "not suppressed" in scf_canonical.detail
    assert scf_canonical.evidence["claim_shape"] == "canonical"
    assert scf_canonical.severity == "medium"

    assert scf_impersonation.severity == "high"
    assert scf_impersonation.evidence["claim_shape"] == "impersonation"
    assert scf_impersonation.detail != scf_canonical.detail

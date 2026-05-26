"""Tests for ``packages.sca.supply_chain.branch_protection``.

Uses a stub client so tests don't hit the live GitHub API. The
stub returns whatever the test fixture configures for
``get_repo_info`` + ``get_branch_protection``, modelling the four
shapes the detector handles:

  * 404 (no protection rule)
  * protection exists, required_signatures=False
  * protection exists, required_signatures=True
  * couldn't query (None)

Plus tests for the .git/config parsing — both HTTPS and SSH remote
URL forms, non-GitHub remotes, malformed configs.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Optional


from packages.sca.supply_chain.branch_protection import (
    _detect_github_remote,
    _parse_github_url,
    scan_target,
)


class _StubClient:
    """Mimics the relevant slice of GitHubActionsClient for tests."""

    def __init__(
        self,
        *,
        repo_info: Optional[Dict] = None,
        branch_protection: Optional[Dict] = None,
    ) -> None:
        self._repo_info = repo_info
        self._branch_protection = branch_protection
        self.get_repo_info_calls = 0
        self.get_branch_protection_calls = 0

    def get_repo_info(self, owner_repo: str):
        self.get_repo_info_calls += 1
        return self._repo_info

    def get_branch_protection(self, owner_repo: str, branch: str):
        self.get_branch_protection_calls += 1
        return self._branch_protection


def _write_git_config(target: Path, remote_url: str) -> None:
    """Write a minimal .git/config carrying a ``[remote "origin"]``
    section with the given URL."""
    (target / ".git").mkdir(parents=True, exist_ok=True)
    (target / ".git" / "config").write_text(
        f'[core]\n'
        f'    repositoryformatversion = 0\n'
        f'[remote "origin"]\n'
        f'    url = {remote_url}\n'
        f'    fetch = +refs/heads/*:refs/remotes/origin/*\n',
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# URL parsing (pure-string).
# ---------------------------------------------------------------------------

def test_parse_github_https_url() -> None:
    assert _parse_github_url(
        "https://github.com/owner/repo.git"
    ) == "owner/repo"
    assert _parse_github_url(
        "https://github.com/owner/repo"
    ) == "owner/repo"
    assert _parse_github_url(
        "https://x-access-token:tok@github.com/owner/repo.git"
    ) == "owner/repo"


def test_parse_github_ssh_url() -> None:
    assert _parse_github_url(
        "git@github.com:owner/repo.git"
    ) == "owner/repo"
    assert _parse_github_url(
        "git@github.com:owner/repo"
    ) == "owner/repo"


def test_parse_github_url_rejects_non_github() -> None:
    """GitLab / Bitbucket / Gitea / self-hosted remotes are not
    GitHub — branch-protection API doesn't apply."""
    assert _parse_github_url(
        "https://gitlab.com/owner/repo.git"
    ) is None
    assert _parse_github_url(
        "https://bitbucket.org/owner/repo"
    ) is None
    assert _parse_github_url("git@gitea.local:owner/repo.git") is None
    assert _parse_github_url("") is None
    assert _parse_github_url("not-a-url") is None


# ---------------------------------------------------------------------------
# .git/config remote detection.
# ---------------------------------------------------------------------------

def test_detect_github_remote_from_https_config(tmp_path: Path) -> None:
    _write_git_config(tmp_path, "https://github.com/me/myrepo.git")
    assert _detect_github_remote(tmp_path) == "me/myrepo"


def test_detect_github_remote_from_ssh_config(tmp_path: Path) -> None:
    _write_git_config(tmp_path, "git@github.com:me/myrepo.git")
    assert _detect_github_remote(tmp_path) == "me/myrepo"


def test_detect_github_remote_returns_none_for_gitlab(
    tmp_path: Path,
) -> None:
    _write_git_config(tmp_path, "https://gitlab.com/me/myrepo.git")
    assert _detect_github_remote(tmp_path) is None


def test_detect_github_remote_returns_none_when_no_config(
    tmp_path: Path,
) -> None:
    """No .git/config — not a git repo, no detection possible."""
    assert _detect_github_remote(tmp_path) is None


def test_detect_github_remote_with_multiple_remotes(
    tmp_path: Path,
) -> None:
    """``[remote "upstream"]`` shouldn't be picked up — we only read
    ``[remote "origin"]``."""
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text(
        '[remote "upstream"]\n'
        '    url = https://github.com/upstream/repo.git\n'
        '[remote "origin"]\n'
        '    url = https://github.com/me/myrepo.git\n',
        encoding="utf-8",
    )
    assert _detect_github_remote(tmp_path) == "me/myrepo"


# ---------------------------------------------------------------------------
# scan_target behaviour.
# ---------------------------------------------------------------------------

def test_no_client_means_no_findings(tmp_path: Path) -> None:
    """No client (offline / no token) → silent no-op."""
    _write_git_config(tmp_path, "https://github.com/me/repo.git")
    assert scan_target(tmp_path, manifests=[], client=None) == []


def test_non_github_remote_means_no_findings(tmp_path: Path) -> None:
    """Branch-protection API is GitHub-specific — for a GitLab
    remote we silently no-op rather than emitting a false positive
    or attempting the wrong API."""
    _write_git_config(tmp_path, "https://gitlab.com/me/repo.git")
    client = _StubClient(repo_info={"default_branch": "main"})
    assert scan_target(tmp_path, manifests=[], client=client) == []
    # We don't even ASK the client (no GitHub remote to query against).
    assert client.get_branch_protection_calls == 0


def test_required_signatures_enabled_means_no_findings(
    tmp_path: Path,
) -> None:
    """The desired posture — branch protection on, signed commits
    required. No finding emitted."""
    _write_git_config(tmp_path, "https://github.com/me/repo.git")
    client = _StubClient(
        repo_info={"default_branch": "main"},
        branch_protection={
            "required_signatures": {"enabled": True},
        },
    )
    findings = scan_target(tmp_path, manifests=[], client=client)
    assert findings == []


def test_missing_signed_commits_emits_low_severity(
    tmp_path: Path,
) -> None:
    """Branch protection exists but doesn't require signed commits.
    Operator has thought about protection but missed the signing
    toggle. Low severity."""
    _write_git_config(tmp_path, "https://github.com/me/repo.git")
    client = _StubClient(
        repo_info={"default_branch": "main"},
        branch_protection={
            "required_signatures": {"enabled": False},
            "required_pull_request_reviews": {},
        },
    )
    findings = scan_target(tmp_path, manifests=[], client=client)
    assert len(findings) == 1
    f = findings[0]
    assert f.finding_shape == "missing_signed_commits"
    assert f.severity == "low"
    assert f.owner_repo == "me/repo"
    assert f.branch == "main"


def test_no_branch_protection_at_all_emits_medium(
    tmp_path: Path,
) -> None:
    """API returned the 404 sentinel — no branch-protection rule
    exists. Higher severity (medium) than missing-signed-commits
    because nothing prevents direct pushes to main."""
    _write_git_config(tmp_path, "https://github.com/me/repo.git")
    client = _StubClient(
        repo_info={"default_branch": "main"},
        branch_protection={"_sentinel": "not_found"},
    )
    findings = scan_target(tmp_path, manifests=[], client=client)
    assert len(findings) == 1
    f = findings[0]
    assert f.finding_shape == "missing_protection"
    assert f.severity == "medium"
    assert f.owner_repo == "me/repo"


def test_branch_protection_query_fails_silently(
    tmp_path: Path,
) -> None:
    """Client returned None — couldn't query (no token, 403, network
    failure). Don't emit a finding; the operator's posture is
    unknowable, better silent than wrong."""
    _write_git_config(tmp_path, "https://github.com/me/repo.git")
    client = _StubClient(
        repo_info={"default_branch": "main"},
        branch_protection=None,
    )
    findings = scan_target(tmp_path, manifests=[], client=client)
    assert findings == []


def test_default_branch_falls_back_to_main(tmp_path: Path) -> None:
    """When the repo-info API also fails, we still try ``main`` as
    the default — covers the most common case."""
    _write_git_config(tmp_path, "https://github.com/me/repo.git")
    client = _StubClient(
        repo_info=None,                # repo-info fail
        branch_protection={
            "required_signatures": {"enabled": False},
        },
    )
    findings = scan_target(tmp_path, manifests=[], client=client)
    assert len(findings) == 1
    assert findings[0].branch == "main"


def test_default_branch_honoured_when_not_main(tmp_path: Path) -> None:
    """Repo's default branch is ``develop``; the detector uses that
    rather than hardcoding ``main``."""
    _write_git_config(tmp_path, "https://github.com/me/repo.git")
    client = _StubClient(
        repo_info={"default_branch": "develop"},
        branch_protection={"_sentinel": "not_found"},
    )
    findings = scan_target(tmp_path, manifests=[], client=client)
    assert findings[0].branch == "develop"


# ---------------------------------------------------------------------------
# Orchestrator integration.
# ---------------------------------------------------------------------------

def test_emits_through_supply_chain_orchestrator(
    tmp_path: Path,
) -> None:
    """End-to-end: the orchestrator wires the new detector behind
    the existing ``github_actions_client`` parameter (same client
    that powers gha_freshness)."""
    from packages.sca.supply_chain import evaluate

    _write_git_config(tmp_path, "https://github.com/me/repo.git")
    client = _StubClient(
        repo_info={"default_branch": "main"},
        branch_protection={"_sentinel": "not_found"},
    )
    findings = evaluate(
        target=tmp_path, manifests=[], deps=[],
        github_actions_client=client,
    )
    bp_findings = [
        f for f in findings
        if f.kind == "branch_protection_missing_signed_commits"
    ]
    assert len(bp_findings) == 1
    f = bp_findings[0]
    assert f.evidence["owner_repo"] == "me/repo"
    assert f.evidence["finding_shape"] == "missing_protection"
    assert f.severity == "medium"
    # Detail explains the threat model so an operator reading the
    # report knows WHY this row exists.
    assert "Megalodon" in f.detail


def test_orchestrator_no_op_without_client(tmp_path: Path) -> None:
    """When the pipeline didn't wire a github_actions_client (offline
    mode, no token), the orchestrator gate keeps branch-protection
    inert — same posture as gha_freshness."""
    from packages.sca.supply_chain import evaluate

    _write_git_config(tmp_path, "https://github.com/me/repo.git")
    findings = evaluate(
        target=tmp_path, manifests=[], deps=[],
        github_actions_client=None,
    )
    bp_findings = [
        f for f in findings
        if f.kind == "branch_protection_missing_signed_commits"
    ]
    assert bp_findings == []

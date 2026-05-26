"""Branch-protection posture detector.

Companion to ``workflow_signing.py``: the workflow-history
detector tells you *what already happened* (someone pushed an
unsigned commit); this detector tells you *whether anything could
prevent it from happening again*.

Specifically: queries GitHub's branch-protection API for the
target repo's default branch and surfaces a finding when
"Require signed commits" isn't enabled. This is the single
GitHub-side toggle that turns the Megalodon-class d-PPE attack
from "credential compromise" into "credential + signing-key
compromise" — a meaningfully higher bar.

Detection shape:

  * Repo has branch protection AND ``required_signatures.enabled``
    is True → no finding (the right posture).
  * Repo has branch protection AND ``required_signatures.enabled``
    is False → ``low`` severity finding. The operator has thought
    about protection but skipped the signing toggle.
  * Repo has no branch protection rule on default branch at all
    → ``medium`` severity finding. Anyone with write can push
    anything to ``main``, signed or not. Megalodon-shape exposure.
  * Can't query (no token / 403 / network) → no finding. Better
    silent than emitting "we couldn't tell" rows.

Auth & token surface:

  GitHub's branch-protection endpoint requires authentication
  with ``administration:read`` (fine-grained tokens) or ``repo``
  (legacy tokens). Anonymous requests always 404. The shared
  ``HttpClient`` reads ``GITHUB_TOKEN`` from the environment;
  the pipeline wires this through to ``GitHubActionsClient``.
  Without a token, this detector quietly no-ops — same posture
  as ``gha_freshness``.

Repo discovery:

  We need ``owner/repo`` to query GitHub. We parse this from
  ``.git/config``'s ``[remote "origin"] url = ...`` line. Both
  ``https://github.com/<owner>/<repo>(.git)?`` and
  ``git@github.com:<owner>/<repo>(.git)?`` formats are
  recognised. Non-GitHub remotes produce no findings.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from ..models import Confidence, Dependency, Manifest, PinStyle

logger = logging.getLogger(__name__)


# Regex matches both URL forms of a GitHub remote. Captures
# (owner, repo) without the ``.git`` suffix.
_GH_HTTPS_RE = re.compile(
    r"^https?://(?:[^@/]+@)?github\.com/"
    r"(?P<owner>[\w.\-]+)/(?P<repo>[\w.\-]+?)"
    r"(?:\.git)?/?\s*$"
)
_GH_SSH_RE = re.compile(
    r"^(?:ssh://)?git@github\.com[:/]"
    r"(?P<owner>[\w.\-]+)/(?P<repo>[\w.\-]+?)"
    r"(?:\.git)?/?\s*$"
)


@dataclass(frozen=True)
class BranchProtectionFinding:
    """Internal carrier. Severity + reason flow from the API
    response shape; the orchestrator converts to a SupplyChainFinding."""

    dependency: Dependency
    owner_repo: str
    branch: str
    finding_shape: str       # "missing_protection" | "missing_signed_commits"
    severity: str
    confidence: Confidence


def scan_target(
    target: Path, manifests: List[Manifest],
    *, client=None,
) -> List[BranchProtectionFinding]:
    """Query GitHub's branch-protection API for the target repo's
    default branch. ``client`` is a ``GitHubActionsClient`` (or stub
    for tests). When None, the detector no-ops (offline / no token
    / pipeline didn't wire the client).
    """
    if client is None:
        return []
    owner_repo = _detect_github_remote(target)
    if owner_repo is None:
        return []
    branch = _detect_default_branch(client, owner_repo)
    if branch is None:
        return []
    protection = client.get_branch_protection(owner_repo, branch)
    if protection is None:
        # Couldn't query (no token, network, etc). Quietly no-op.
        return []
    host = _placeholder_host(target, owner_repo)
    if protection.get("_sentinel") == "not_found":
        return [BranchProtectionFinding(
            dependency=host,
            owner_repo=owner_repo,
            branch=branch,
            finding_shape="missing_protection",
            severity="medium",
            confidence=Confidence(
                "high",
                reason=(
                    "GitHub API reports no branch-protection rule "
                    "on the default branch"
                ),
            ),
        )]
    req_sig = (protection.get("required_signatures") or {})
    if req_sig.get("enabled") is True:
        return []  # the right posture
    return [BranchProtectionFinding(
        dependency=host,
        owner_repo=owner_repo,
        branch=branch,
        finding_shape="missing_signed_commits",
        severity="low",
        confidence=Confidence(
            "high",
            reason=(
                "branch-protection rule exists but "
                "required_signatures.enabled is false"
            ),
        ),
    )]


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _detect_github_remote(target: Path) -> Optional[str]:
    """Return ``owner/repo`` for the target's ``origin`` remote, or
    None when the remote isn't a GitHub one (or no .git config)."""
    config = target / ".git" / "config"
    if not config.is_file():
        return None
    try:
        text = config.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    # Walk for the [remote "origin"] section's url. Simple line-
    # scanning rather than ConfigParser because .git/config uses
    # extended sections (``[remote "origin"]``) that the stdlib
    # parser handles awkwardly.
    in_origin = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            in_origin = (line == '[remote "origin"]')
            continue
        if not in_origin:
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        if key.strip() != "url":
            continue
        url = value.strip()
        slug = _parse_github_url(url)
        if slug is not None:
            return slug
    return None


def _parse_github_url(url: str) -> Optional[str]:
    """``https://github.com/Foo/bar.git`` → ``Foo/bar``;
    ``git@github.com:Foo/bar.git`` → ``Foo/bar``. None for non-
    GitHub remotes (GitLab, Bitbucket, self-hosted Gitea / Forgejo,
    etc.) — branch-protection-API is GitHub-specific."""
    for rgx in (_GH_HTTPS_RE, _GH_SSH_RE):
        m = rgx.match(url)
        if m is not None:
            return f"{m.group('owner')}/{m.group('repo')}"
    return None


def _detect_default_branch(client, owner_repo: str) -> Optional[str]:
    """Ask GitHub for the repo's default branch via
    ``GET /repos/{owner}/{repo}``. Falls back to ``main`` when the
    API call fails — the operator-most-common name. Truly weird
    defaults (``trunk``, ``develop``) are surfaced by the API call;
    we don't try to be clever."""
    info = client.get_repo_info(owner_repo)
    if isinstance(info, dict):
        branch = info.get("default_branch")
        if isinstance(branch, str) and branch:
            return branch
    return "main"


def _placeholder_host(target: Path, owner_repo: str) -> Dependency:
    return Dependency(
        ecosystem="GitHub Actions",
        name=f"<branch-protection:{owner_repo}>",
        version=None,
        declared_in=target / ".git" / "config",
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.UNKNOWN,
        direct=True,
        purl="",
        parser_confidence=Confidence(
            "low",
            reason="placeholder for branch-protection finding host",
        ),
    )


__all__ = [
    "BranchProtectionFinding",
    "scan_target",
]

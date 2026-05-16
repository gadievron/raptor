"""
Three hard checks on the agent's discover output.

Replaces ``cve_diff/recovery/validators.py``. The old validator re-ran
the 7-gate scorer chain and killed correct agent picks (see
``project_recovery_zero_rescue_rootcause.md``). This one does not score
and uses no hardcoded slug / tracker / keyword list — it only enforces
invariants whose absence produced the reference project's Bug #1 /
Bug #12 plus the hallucinated-SHA failure caught in the 2026-04-24
smoke (CVE-2023-38545: agent submitted
fb4415d8aee6c14a9ec300ca28dfe318fe85e1cc — same 14-char prefix as
the real curl SHA, confabulated middle):

  1. Type invariants — ``PatchTuple`` construction + ``is_valid_sha_format``.
     Defends Bug #1 / #12.
  2. SHA exists in the GitHub repo — ``github_client.commit_exists(slug, sha)``.
     Defends against the hallucinated-SHA failure mode. Skipped on non-
     GitHub URLs (cgit/savannah/freedesktop/gitlab) and on rate-limit
     (returns None) — non-decision is not a rejection.
  3. Shape sanity — checked *after* the diff runs, via ``check_diff_shape``
     called from ``pipeline.py``. Rejects ``notes_only`` diffs that
     would indicate a tracker / writeup repo rather than upstream.

**No tracker-repo filter.** The previous check 2 called
``canonical.score(url) > 0`` which internally depended on a 72-regex
``TRACKER_REPO_PATTERNS`` list — a hardcoded corpus of known-bad
slugs. That violates the no-lists mandate. Tracker-repo smell is now
agent-time judgment (prompted) plus post-acquire shape sanity.
"""

from __future__ import annotations

from cve_diff.agent.types import AgentContext, AgentOutput, AgentResult, AgentSurrender
from cve_diff.core.models import CommitSha, PatchTuple
from core.url_patterns import extract_github_slug as _github_slug
from cve_diff.diffing.commit_resolver import CommitResolver
from cve_diff.infra import github_client

_resolver = CommitResolver()


def discover_validator(payload: dict, ctx: AgentContext) -> AgentResult:
    """Validate the agent's ``submit_result`` payload and return an
    ``AgentOutput(PatchTuple)`` or ``AgentSurrender(reason)``."""
    outcome = (payload.get("outcome") or "").strip()
    rationale = (payload.get("rationale") or "")[:500]

    if outcome == "unsupported":
        return AgentSurrender(reason="unsupported_source", detail=rationale)
    if outcome == "no_evidence":
        return AgentSurrender(reason="no_evidence", detail=rationale)
    if outcome != "rescued":
        return AgentSurrender(reason="invalid_outcome", detail=f"outcome={outcome!r}")

    repo_url = (payload.get("repository_url") or "").strip()
    fix_commit = (payload.get("fix_commit") or "").strip()

    # Check 1: type invariants — SHA format, then PatchTuple __post_init__.
    if not _resolver.is_valid_sha_format(fix_commit):
        return AgentSurrender(
            reason="invalid_sha_format",
            detail=f"fix_commit={fix_commit[:80]!r}",
        )

    # Check 2: SHA exists in the GitHub repo. Only enforceable when the URL
    # is GitHub-shaped — non-GitHub forges (cgit, savannah, freedesktop,
    # gitlab) get skipped. ``commit_exists`` returns:
    #   True  → accept
    #   False → REJECT (hallucinated SHA — the smoke caught a fb4415d8...
    #           SHA that shared the curl fix's first 14 chars but didn't
    #           exist on the remote)
    #   None  → could not determine (rate-limited / auth issue) — accept
    #
    # Minimal URL sanity (must look like http(s)) lives here too so a
    # completely bogus repository_url gets rejected before we try
    # acquisition. No slug-content list lookup.
    if not repo_url.lower().startswith(("http://", "https://")):
        return AgentSurrender(
            reason="malformed_repository_url",
            detail=f"repository_url={repo_url[:200]!r}",
        )
    slug = _github_slug(repo_url)
    if slug is not None:
        exists = github_client.commit_exists(slug, fix_commit)
        if exists is False:
            return AgentSurrender(
                reason="sha_not_found_in_repo",
                detail=f"{slug}@{fix_commit[:12]} returned 404",
            )

    # PatchTuple construction runs the frozen-dataclass guardrails
    # (non-empty url, non-empty fix_commit). A malformed payload that
    # slipped both prior checks raises here, which we catch and convert
    # to an AgentSurrender so the loop always returns a valid AgentResult.
    try:
        patch = PatchTuple(
            repository_url=repo_url,
            fix_commit=CommitSha(fix_commit),
            introduced=None,
        )
    except ValueError as exc:
        return AgentSurrender(reason="patch_tuple_invalid", detail=str(exc)[:200])

    return AgentOutput(value=patch, rationale=rationale)


def check_diff_shape(shape: str) -> str | None:
    """Called by ``pipeline.py`` *after* ``diffing/extractor.py`` has
    classified the patch. Returns a reason string when the diff should be
    rejected and the agent re-invoked, else ``None``.

    Only ``notes_only`` is a hard reject: a patch that touches only
    release-notes / changelog files is almost certainly a downstream
    mirror's commit, not the upstream fix. ``packaging_only`` is not
    rejected here — some legitimate patches in the dataset are pure
    version bumps (distro advisory fixes).
    """
    if shape == "notes_only":
        return "notes_only_diff"
    return None

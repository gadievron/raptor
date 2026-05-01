"""GitHub Commits API as a fallback source-extraction method.

When ``git clone`` + ``git diff fix^..fix`` fails (acquisition error,
oversized repo, "unadvertised object" git server), this module
extracts the same diff content via ``GET /repos/{slug}/commits/{sha}``.

**Bug #12 guarantee** (no HEAD fallback):
- The GitHub API endpoint requires a fully-qualified SHA. Passing
  literal ``"HEAD"`` returns 404. Passing a tag returns 422.
- We assert SHA-format BEFORE calling — same regex as
  ``commit_resolver.is_valid_sha_format`` — so an upstream bug that
  tries to extract from a tag/branch is rejected at the boundary.
- The diff is always between ``commit.parents[0].sha`` and
  ``commit.sha`` — i.e., ``fix^..fix``, identical to the clone-based
  extractor. We do NOT call any "compare against HEAD" or "diff
  against latest" variant of the API.

Predecessor lesson (CLAUDE.md): the deleted ``recovery/diff_methods.py``
+ ``edge_case_handler.py`` totaled 1000+ LOC for multi-method
extraction and never out-performed the one-liner ``git diff``. We're
NOT re-porting that. This module adds ONE fallback method (the
GitHub API) targeted at the specific failure shape we still see
(clone fails for repo-protocol or size reasons).
"""

from __future__ import annotations

import re

from cve_diff.core.exceptions import AnalysisError
from cve_diff.core.models import (
    CommitSha,
    DiffBundle,
    FileChange,
    RepoRef,
)
from cve_diff.diffing import shape_dynamic
from cve_diff.infra import github_client

# Same SHA acceptance as commit_resolver._SHA_RE — keep in sync.
_SHA_RE = re.compile(r"^[0-9a-f]{7,40}$", re.IGNORECASE)
_INVALID_LITERALS = {"head", "main", "master", "trunk", "0", "none", "null", ""}


def _slug_of(repo_url: str) -> str | None:
    """Extract `owner/repo` from a GitHub URL. Reused by shape classifier.

    Delegates to ``core.url_re.extract_github_slug`` so the same regex
    that fixed dotted-name truncation (``engine.io`` → ``engine``,
    2026-04-26) is in force here too. Previously this had its own
    inline regex that excluded ``.`` from the repo segment, which made
    ``compute_extraction_agreement`` silently fall back to
    ``single_source`` for any repo with a dotted name.
    """
    from cve_diff.core.url_re import extract_github_slug
    return extract_github_slug(repo_url or "")


def extract_via_api(
    cve_id: str,
    ref: RepoRef,
) -> DiffBundle:
    """Fetch the commit diff via GitHub API instead of git clone.

    Raises ``AnalysisError`` if:
    - The repo URL isn't a GitHub URL (API path only supports github.com).
    - The fix_commit isn't a valid SHA (Bug #12 defense).
    - The API returns no commit (404, rate-limit, or network failure).
    - The API response has no parents (root commit) — we can't compute
      `fix^..fix` without a parent (clone-based extractor handles this
      via the empty-tree-SHA fallback; here we propagate as a clear error).
    """
    sha = (ref.fix_commit or "").strip().lower()
    if sha in _INVALID_LITERALS or not _SHA_RE.match(sha):
        raise AnalysisError(
            f"{cve_id}: extract_via_api refused — fix_commit "
            f"{ref.fix_commit!r} is not a SHA (Bug #12 defense)"
        )

    slug = _slug_of(ref.repository_url)
    if slug is None:
        raise AnalysisError(
            f"{cve_id}: extract_via_api supports github.com URLs only "
            f"(got {ref.repository_url!r})"
        )

    payload = github_client.get_commit(slug, sha)
    if payload is None:
        raise AnalysisError(
            f"{cve_id}: GitHub commit API returned no data for {slug}@{sha[:12]} "
            f"(404 / rate-limit / network failure)"
        )

    parents = payload.get("parents") or []
    if not parents or not isinstance(parents[0], dict) or not parents[0].get("sha"):
        raise AnalysisError(
            f"{cve_id}: commit {slug}@{sha[:12]} has no parent — "
            f"can't compute fix^..fix via API (root commit)"
        )
    parent_sha = parents[0]["sha"].lower()

    files_raw = payload.get("files") or []
    if not isinstance(files_raw, list):
        raise AnalysisError(
            f"{cve_id}: API response 'files' is not a list "
            f"(got {type(files_raw).__name__})"
        )

    # Build unified diff text by concatenating per-file patches.
    # Each file in the API response has a `patch` field with hunks.
    diff_chunks: list[str] = []
    file_names: list[str] = []
    files: list[FileChange] = []
    for entry in files_raw:
        if not isinstance(entry, dict):
            continue
        path = entry.get("filename") or ""
        if not path:
            continue
        file_names.append(path)
        patch = entry.get("patch") or ""
        if patch:
            # Synthesize a `diff --git` header so the output looks like
            # what `git diff` produces.
            diff_chunks.append(
                f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n{patch}\n"
            )
        files.append(
            FileChange(
                path=path,
                is_test=_is_test_path(path),
                hunks_count=patch.count("\n@@ ") + (1 if patch.startswith("@@ ") else 0),
                # API doesn't return full file contents — just patch hunks.
                # Clone-based extractor populates these blobs; the API path
                # leaves them None to signal "not available via this method".
                before_source=None,
                after_source=None,
            )
        )

    diff_text = "\n".join(diff_chunks)

    if not file_names and not diff_text:
        raise AnalysisError(
            f"{cve_id}: API returned commit {slug}@{sha[:12]} with no file changes"
        )

    shape = shape_dynamic.classify(
        file_names,
        slug=slug,
        fetch=github_client.get_languages,
    )

    return DiffBundle(
        cve_id=cve_id,
        repo_ref=ref,
        commit_before=CommitSha(parent_sha),
        commit_after=CommitSha(sha),
        diff_text=diff_text,
        files_changed=len(file_names),
        bytes_size=len(diff_text.encode("utf-8")),
        shape=shape,
        files=tuple(files),
    )


_TEST_PATH_RE = re.compile(
    r"(^|/)(tests?|spec|specs?|__tests__|fixtures?)/|(^|/)test_[^/]*$|"
    r"_test\.[^/]+$|\.test\.[^/]+$|\.spec\.[^/]+$",
    re.IGNORECASE,
)


def _is_test_path(path: str) -> bool:
    return bool(_TEST_PATH_RE.search(path or ""))

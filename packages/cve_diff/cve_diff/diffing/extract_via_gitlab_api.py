"""GitLab-API diff extractor + forge-aware dispatcher.

Closes the diff-capability gap surfaced 2026-04-30: the
``compute_extraction_agreement`` cross-check only ran for GitHub-hosted
CVEs because ``extract_via_api`` knew only the GitHub API. About 10 %
of PASSes (every gitlab.com / gitlab.freedesktop.org / similar repo)
shipped with ``extraction_agree=single_source``.

This module:
  * adds ``extract_via_gitlab_api`` — a parallel of ``extract_via_api``
    that talks to the GitLab v4 REST API. Works for gitlab.com and
    self-hosted GitLab (gitlab.freedesktop.org and similar).
  * exports ``extract_for_agreement`` — a forge-aware dispatcher that
    ``compute_extraction_agreement`` calls instead of going straight
    to the GitHub-specific extractor. Returns ``None`` for forges we
    can't cross-check (savannah cgit, googlesource); the agreement
    layer treats that as ``single_source``.
"""
from __future__ import annotations

import re
from typing import Optional

import requests

from cve_diff.core.exceptions import AnalysisError
from cve_diff.core.models import CommitSha, DiffBundle, FileChange, RepoRef
from cve_diff.core.test_path import is_test_path as _is_test_path
from cve_diff.diffing import shape_dynamic
from cve_diff.diffing.extract_via_api import (
    extract_via_api as _extract_via_api_github,
)


_TIMEOUT_S = 10.0
_GITLAB_HOST_RE = re.compile(
    r"^(https?://(?:gitlab\.com|gitlab\.[^/]+))/"
    r"([^?#]+?)/?$",
    re.IGNORECASE,
)


def _gitlab_host_and_slug(repo_url: str) -> tuple[Optional[str], Optional[str]]:
    """Return ``(host, slug)`` for a GitLab URL, or ``(None, None)``.

    Recognises ``gitlab.com`` and self-hosted GitLab (any host whose
    name starts with ``gitlab.``). Strips trailing ``/`` and ``.git``.
    Preserves nested group/subgroup paths (GitLab supports them).
    """
    if not repo_url:
        return None, None
    m = _GITLAB_HOST_RE.match(repo_url.strip())
    if not m:
        return None, None
    host = m.group(1)
    slug = m.group(2)
    if slug.endswith(".git"):
        slug = slug[:-4]
    return host, slug


def extract_via_gitlab_api(cve_id: str, ref: RepoRef) -> DiffBundle:
    """Fetch the commit diff via GitLab v4 API.

    Parallels ``extract_via_api`` (GitHub) — same return shape,
    same ``AnalysisError`` cases:
      * non-GitLab URL → AnalysisError
      * 404 / network → AnalysisError
      * root commit (no parents) → AnalysisError

    Two API calls per CVE:
      ``GET /api/v4/projects/{slug}/repository/commits/{sha}`` for the
      parent SHA + commit metadata, then
      ``GET /api/v4/projects/{slug}/repository/commits/{sha}/diff`` for
      the per-file diffs.
    """
    host, slug = _gitlab_host_and_slug(ref.repository_url)
    if host is None or slug is None:
        raise AnalysisError(
            f"{cve_id}: extract_via_gitlab_api supports gitlab URLs only "
            f"(got {ref.repository_url!r})"
        )

    sha = (ref.fix_commit or "").strip().lower()
    encoded = requests.utils.quote(slug, safe="")
    base = f"{host}/api/v4/projects/{encoded}/repository/commits/{sha}"

    try:
        meta_resp = requests.get(base, timeout=_TIMEOUT_S)
    except requests.RequestException as exc:
        raise AnalysisError(
            f"{cve_id}: GitLab commit API network error for {slug}@{sha[:12]}: {exc}"
        ) from exc
    if meta_resp.status_code != 200:
        raise AnalysisError(
            f"{cve_id}: GitLab commit API returned http {meta_resp.status_code} "
            f"for {slug}@{sha[:12]}"
        )
    try:
        meta = meta_resp.json()
    except ValueError as exc:
        raise AnalysisError(
            f"{cve_id}: GitLab commit API returned non-JSON for {slug}@{sha[:12]}"
        ) from exc

    parents = meta.get("parent_ids") or []
    if not parents or not isinstance(parents[0], str):
        raise AnalysisError(
            f"{cve_id}: commit {slug}@{sha[:12]} has no parent — "
            f"can't compute fix^..fix via API (root commit)"
        )
    parent_sha = parents[0].lower()

    try:
        diff_resp = requests.get(f"{base}/diff", timeout=_TIMEOUT_S)
    except requests.RequestException as exc:
        raise AnalysisError(
            f"{cve_id}: GitLab diff API network error: {exc}"
        ) from exc
    if diff_resp.status_code != 200:
        raise AnalysisError(
            f"{cve_id}: GitLab diff API returned http {diff_resp.status_code}"
        )
    try:
        diff_entries = diff_resp.json()
    except ValueError as exc:
        raise AnalysisError(
            f"{cve_id}: GitLab diff API returned non-JSON"
        ) from exc

    if not isinstance(diff_entries, list):
        raise AnalysisError(
            f"{cve_id}: GitLab diff API response was not a list "
            f"(got {type(diff_entries).__name__})"
        )

    diff_chunks: list[str] = []
    file_names: list[str] = []
    files: list[FileChange] = []
    for entry in diff_entries:
        if not isinstance(entry, dict):
            continue
        path = entry.get("new_path") or entry.get("old_path") or ""
        if not path:
            continue
        file_names.append(path)
        body = entry.get("diff") or ""
        if body:
            diff_chunks.append(
                f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n{body}"
            )
        files.append(
            FileChange(
                path=path,
                is_test=_is_test_path(path),
                hunks_count=body.count("\n@@ ") + (1 if body.startswith("@@ ") else 0),
                before_source=None,
                after_source=None,
            )
        )

    diff_text = "\n".join(diff_chunks)
    if not file_names and not diff_text:
        raise AnalysisError(
            f"{cve_id}: GitLab diff API returned 0 file changes for {slug}@{sha[:12]}"
        )

    # Shape classification: shape_dynamic.classify expects a `fetch`
    # callback for `/languages`; for GitLab we don't have that endpoint
    # mapped, so pass a no-op fetch — classifier falls back to the
    # static path (good enough for "packaging vs source" on the file
    # name list; the agreement check primarily compares files+bytes).
    shape = shape_dynamic.classify(
        file_names, slug=slug, fetch=lambda _slug: None,
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


def extract_for_agreement(
    cve_id: str, ref: RepoRef,
) -> list[tuple[str, DiffBundle]]:
    """Forge-aware multi-source dispatcher.

    Returns a list of ``(method_name, DiffBundle)`` tuples — one per
    second-source that succeeded. Each method is independent; one
    failing doesn't sink the others. The empty list means "no second
    source available for this forge" (caller renders ``single source``).

    Methods (when available):

      * ``github_api`` / ``gitlab_api`` — JSON commits API.
      * ``patch_url`` — the forge's raw ``<sha>.patch`` text endpoint
        (GitHub, GitLab, cgit/kernel.org). Distinct from the JSON path,
        so it adds real triangulation. First second-source coverage
        for cgit-hosted CVEs.

    Per-extractor failures (network errors, AnalysisError, 404) are
    swallowed: that source is just absent from the returned list.
    """
    # Defer import to avoid an early circular dependency (the patch-URL
    # extractor itself imports `_gitlab_host_and_slug` from this module).
    from cve_diff.diffing.extract_via_patch_url import extract_via_patch_url

    results: list[tuple[str, DiffBundle]] = []

    url = (ref.repository_url or "").lower()
    # JSON API path (per-forge).
    if "github.com" in url:
        try:
            b = _extract_via_api_github(cve_id, ref)
            if b is not None:
                results.append(("github_api", b))
        except AnalysisError:
            pass
    elif _gitlab_host_and_slug(ref.repository_url) != (None, None):
        try:
            b = extract_via_gitlab_api(cve_id, ref)
            if b is not None:
                results.append(("gitlab_api", b))
        except AnalysisError:
            pass

    # Patch-URL path: works on GitHub, GitLab, cgit. Independent of the
    # JSON path — we get triangulation when both succeed and at least
    # one second source when the JSON path is unavailable (cgit).
    try:
        b = extract_via_patch_url(cve_id, ref)
        if b is not None:
            results.append(("patch_url", b))
    except Exception:  # noqa: BLE001 — auxiliary, never block
        pass

    return results

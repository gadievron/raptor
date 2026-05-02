"""Cross-check the clone-based diff against alternative extractors.

Three diff sources may run for a single CVE:

  1. **Clone** — `git clone` + `git diff fix^..fix` (always, unless
     the clone itself failed).
  2. **Forge API JSON** — GitHub `/repos/{slug}/commits/{sha}` or
     GitLab `/projects/.../repository/commits/{sha}/diff`. JSON, not
     git on the client. Skipped on cgit / unsupported forges.
  3. **Forge `.patch` URL** — the raw ``git format-patch``-style text
     served by the forge (added 2026-04-30, see
     `extract_via_patch_url`). Distinct from the API JSON path; works
     on cgit too.

Two-of-three or three-of-three agreement gives the report layer the
"independent sources matched the captured patch" signal — the user's
primary integrity check.

Cost is near-zero: shared `lru_cache` with the agent's existing
`gh_commit_detail` calls, plus one extra HTTP fetch for the patch URL.
Truncation-aware: GitHub API caps at ~300 files per commit; when that
hits, the API source is downweighted rather than treated as an outlier.
"""
from __future__ import annotations

from cve_diff.core.exceptions import AnalysisError
from cve_diff.core.models import DiffBundle, RepoRef
from cve_diff.diffing.extract_via_gitlab_api import extract_for_agreement

# Pairwise thresholds: clone vs API byte counts are usually within a
# few percent (mostly whitespace / line-ending differences in how each
# extractor renders the diff — git-diff vs GitHub API JSON vs the
# .patch URL's raw body). Above ``_BYTES_AGREE_PCT`` we mark partial;
# above ``_BYTES_PARTIAL_PCT`` we mark disagree.
#
# These thresholds are heuristic — chosen so a typical "render-only
# difference" lands in agree, a meaningful "different parts of the
# fix" lands in disagree, and the messy middle goes to partial. They
# have NOT been formally calibrated against a labelled disagreement
# corpus; if a future bench shows agree/partial/disagree distribution
# is materially off, these are the knobs to tune. Not exposed as
# config — operators shouldn't tune the boundary at runtime; bench
# does it offline.
_BYTES_AGREE_PCT = 0.05
_BYTES_PARTIAL_PCT = 0.25
# GitHub API caps at 300 files per /commits/{sha} response. When file
# count hits this, treat as truncated rather than as a real disagreement.
_API_FILE_CAP = 300


def compute_extraction_agreement(
    cve_id: str, ref: RepoRef, clone_bundle: DiffBundle,
) -> tuple[dict, list[tuple[str, DiffBundle]]] | None:
    """Compute the N-source extraction-agreement signal.

    Returns ``(agreement_dict, extras_list)`` on success — the summary
    dict (for ``DiffBundle.extraction_agreement``) plus a list of
    ``(method_name, DiffBundle)`` tuples for every second-source that
    succeeded. The caller persists each bundle's diff body as
    ``<cve>.<method>.patch`` for audit.

    Returns ``None`` when no second source was available (unsupported
    forge with no patch URL either, or every extractor failed). Never
    blocks the pipeline on this auxiliary check.

    The forge dispatcher (``extract_for_agreement`` in
    ``extract_via_gitlab_api``) returns a list of ``(method, bundle)``
    pairs — usually 2 for GitHub (api + patch_url), 1-2 for GitLab,
    and 1 for cgit (patch_url only).
    """
    try:
        extras = extract_for_agreement(cve_id, ref)
    except AnalysisError:
        # The dispatcher should swallow per-extractor errors internally,
        # but defend against an unexpected re-raise.
        return None
    if not extras:
        return None
    bundles_named: list[tuple[str, DiffBundle]] = [("clone", clone_bundle), *extras]
    summary = _summarize_n(bundles_named)
    return summary, list(extras)


def _compare(clone: DiffBundle, api: DiffBundle) -> dict:
    """Pairwise comparison preserved for callers that want a 2-source
    verdict directly. Internally delegates to ``_compare_pair``. Returns
    the historical dict shape so existing tests / on-disk Markdown
    rendering keep working unchanged."""
    paths_clone = {f.path for f in clone.files}
    paths_api = {f.path for f in api.files}
    union = paths_clone | paths_api
    intersection = paths_clone & paths_api
    overlap = (len(intersection) / len(union)) if union else 1.0

    bytes_clone = max(clone.bytes_size, 1)  # avoid div-by-zero
    pct_diff = abs(api.bytes_size - clone.bytes_size) / bytes_clone

    api_truncated = api.files_changed >= _API_FILE_CAP

    if api_truncated:
        verdict = "partial"   # comparison advisory; API ran out of room
    elif (
        clone.files_changed == api.files_changed
        and overlap == 1.0
        and pct_diff <= _BYTES_AGREE_PCT
    ):
        verdict = "agree"
    elif overlap >= 0.8 and pct_diff <= _BYTES_PARTIAL_PCT:
        verdict = "partial"
    else:
        verdict = "disagree"

    return {
        "method": "clone+api",
        "files_clone": clone.files_changed,
        "files_api": api.files_changed,
        "paths_overlap": round(overlap, 3),
        "bytes_clone": clone.bytes_size,
        "bytes_api": api.bytes_size,
        "bytes_pct_diff": round(pct_diff, 3),
        "api_truncated": api_truncated,
        "verdict": verdict,
    }


def _compare_pair(a: DiffBundle, b: DiffBundle) -> str:
    """Return just the pairwise verdict (`agree`/`partial`/`disagree`).

    Used by the N-source summarizer where only the verdict label
    matters. Reuses the same thresholds as `_compare`.
    """
    paths_a = {f.path for f in a.files}
    paths_b = {f.path for f in b.files}
    union = paths_a | paths_b
    inter = paths_a & paths_b
    overlap = (len(inter) / len(union)) if union else 1.0
    bytes_a = max(a.bytes_size, 1)
    pct = abs(b.bytes_size - a.bytes_size) / bytes_a
    if (a.files_changed == b.files_changed and overlap == 1.0
            and pct <= _BYTES_AGREE_PCT):
        return "agree"
    if overlap >= 0.8 and pct <= _BYTES_PARTIAL_PCT:
        return "partial"
    return "disagree"


def _summarize_n(bundles_named: list[tuple[str, DiffBundle]]) -> dict:
    """N-source agreement summary.

    Builds pairwise verdicts for every (a,b) pair and a top-level
    verdict:

      * ``agree``           — every pair agrees
      * ``majority_agree``  — most pairs agree but at least one
                              source is an outlier (named in
                              ``outliers``)
      * ``disagree``        — no pair agrees
      * ``partial``         — at least one ``partial``, no clear
                              majority

    Output dict shape:

      * ``verdict``  — top-level label
      * ``sources``  — ``[{name, files, bytes}, ...]``, one per source
      * ``pairwise`` — ``{"a:b": verdict, ...}``, deterministic order
      * ``outliers`` — methods that disagreed with the majority (only
                       present for ``majority_agree``)

    For 2 sources the "majority" concept reduces to a single pair —
    verdict is just the pair's label.
    """
    sources = [
        {"name": name, "files": b.files_changed, "bytes": b.bytes_size}
        for name, b in bundles_named
    ]

    if len(bundles_named) < 2:
        # Defensive: shouldn't happen — caller filters empty extras.
        return {"verdict": "single_source", "sources": sources, "pairwise": {}}

    # Build pairwise table.
    pairwise: dict[str, str] = {}
    for i, (na, ba) in enumerate(bundles_named):
        for nb, bb in bundles_named[i + 1:]:
            pairwise[f"{na}:{nb}"] = _compare_pair(ba, bb)

    if len(bundles_named) == 2:
        only = next(iter(pairwise.values()))
        return {"verdict": only, "sources": sources, "pairwise": pairwise}

    # 3+ sources: derive top-level verdict from pairwise distribution.
    # Per-source disagreement count (a source is an "outlier" if every
    # pair involving it is disagree/partial).
    names = [n for n, _ in bundles_named]
    disagree_count = {n: 0 for n in names}
    for key, v in pairwise.items():
        if v == "disagree":
            a, b = key.split(":", 1)
            disagree_count[a] += 1
            disagree_count[b] += 1

    # All pairs agree?
    if all(v == "agree" for v in pairwise.values()):
        return {"verdict": "agree", "sources": sources, "pairwise": pairwise}

    # All pairs disagree?
    if all(v == "disagree" for v in pairwise.values()):
        return {"verdict": "disagree", "sources": sources, "pairwise": pairwise}

    # Majority: there's some pair that agrees, with a clear odd-one-out.
    # An outlier is a source that disagrees with every other source.
    outliers = [
        n for n in names
        if disagree_count[n] == len(names) - 1
    ]
    if outliers:
        return {
            "verdict": "majority_agree",
            "sources": sources,
            "pairwise": pairwise,
            "outliers": outliers,
        }

    # No clear majority — call it partial (mixed agree/partial).
    return {"verdict": "partial", "sources": sources, "pairwise": pairwise}

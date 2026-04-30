"""
Typed invariants for the pipeline.

The reference project's post-mortems boil down to a handful of type confusions
that a strict dataclass layer would have caught at construction time:

- Bug #1: OSV's `introduced` is a *version marker*, not a commit SHA. Treating
  it as a commit produced 3.5-year diffs. Fixed here by exposing `IntroducedMarker`
  and `CommitSha` as distinct NewTypes — a discoverer that returns an
  introduced version cannot accidentally flow into the diff command.
- Bug #2: `zip(repos, fixes, introduceds)` de-synchronised under pagination.
  `PatchTuple` makes the triple atomic.
- Bug #12: `git diff HEAD` was used as a silent fallback. `RepoRef` has no
  default for `fix_commit`; a None slips through the type checker.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import NewType

CommitSha = NewType("CommitSha", str)
IntroducedMarker = NewType("IntroducedMarker", str)


@dataclass(frozen=True, slots=True)
class PatchTuple:
    """
    A single (repo, fix, introduced?) triple. `introduced` is optional because
    many OSV records carry only a version marker — the parent of `fix_commit`
    is then resolved via `git rev-parse fix_commit^`.
    """

    repository_url: str
    fix_commit: CommitSha
    introduced: IntroducedMarker | CommitSha | None = None

    def __post_init__(self) -> None:
        if not self.repository_url:
            raise ValueError("PatchTuple.repository_url cannot be empty")
        if not self.fix_commit:
            raise ValueError("PatchTuple.fix_commit cannot be empty")


@dataclass(frozen=True, slots=True)
class RepoRef:
    """
    A canonical-scored reference to a repo + its two commits. Construction
    requires an explicit `canonical_score` ≥ 0 so the pipeline refuses to act
    on a tracker-redirect (Bug #5: 98.6% of unscored refs resolved to trackers).
    """

    repository_url: str
    fix_commit: CommitSha
    introduced: IntroducedMarker | CommitSha | None
    canonical_score: int

    def __post_init__(self) -> None:
        if not self.repository_url:
            raise ValueError("RepoRef.repository_url cannot be empty")
        if not self.fix_commit:
            raise ValueError("RepoRef.fix_commit cannot be empty")
        if self.canonical_score < 0:
            raise ValueError("RepoRef.canonical_score must be ≥ 0")


@dataclass(frozen=True, slots=True)
class DiscoveryResult:
    """
    What a single discoverer returns. `tuples` may be empty (miss).

    `raw` carries the full upstream payload (currently only populated by the
    OSV discoverer). The cascade extracts `AdvisoryContext` from it and passes
    the context to later discoverers' scoring so wrong-repo matches get
    rejected without a hand-curated slug map.
    """

    source: str
    tuples: tuple[PatchTuple, ...] = field(default_factory=tuple)
    confidence: int = 0
    raw: dict | None = None


@dataclass(frozen=True, slots=True)
class FileChange:
    """
    Per-file breakdown of a single file touched by the patch.

    Fields:
      - `path`          : file path at `commit_after`
      - `is_test`       : heuristic — path matches a test-file pattern
      - `hunks_count`   : number of ``@@`` hunks in this file's diff
      - `before_source` : content at `commit_before` (None if added or extract failed)
      - `after_source`  : content at `commit_after`  (None if deleted or extract failed)

    Source blobs are truncated to the extractor's `MAX_FILE_BYTES` so
    multi-megabyte generated files don't bloat the OSV output.
    """

    path: str
    is_test: bool
    hunks_count: int
    before_source: str | None = None
    after_source: str | None = None


@dataclass(frozen=True, slots=True)
class DiffBundle:
    """
    Output of the extract stage — what the report layer consumes.

    `shape` is the classification of the changed file set:
      - "source"         : at least one source file changed (the normal case)
      - "packaging_only" : only packaging / version manifest files changed
      - "notes_only"     : only release-notes / changelog files changed
    A non-"source" shape is a signal that the CVE's discovered repo is likely
    a downstream packaging mirror rather than the upstream fix source.

    `files` is a per-file structured view (populated by `extract_diff`).
    Empty tuple when the extractor fallback path is used.

    `consensus` is the 2-method pointer-consensus dict (see
    `cve_diff/report/consensus.ConsensusReport.to_dict()`). May be
    None when consensus is skipped (e.g., during the bench's tight
    inner loop where it'd inflate cost). Surfaced in the per-CVE
    markdown report and the OSV `database_specific.consensus` field.

    `extraction_agreement` is the cross-check between the clone-based
    diff (this bundle) and a parallel ``extract_via_api`` pull on the
    same ``(slug, sha)`` for GitHub-hosted commits. Captures whether
    two independent extraction methods agree on the file set / byte
    count of the diff. Keys when present:
      - ``method``: ``"clone+api"`` (always — single key today)
      - ``files_clone`` / ``files_api``: int file counts
      - ``paths_overlap``: float in [0, 1] — Jaccard of touched paths
      - ``bytes_clone`` / ``bytes_api``: int diff bytes
      - ``bytes_pct_diff``: float — relative size delta (clone-side
        baseline). Loose ±5% tolerance is the agreement threshold.
      - ``api_truncated``: bool — True when API response capped at
        ~300 files; comparison is then advisory only.
      - ``verdict``: ``"agree"`` / ``"partial"`` / ``"disagree"`` /
        ``"single_source"``.
    None when no second source was attempted (non-GitHub URL, API
    fallback path itself, or feature disabled).
    """

    cve_id: str
    repo_ref: RepoRef
    commit_before: CommitSha
    commit_after: CommitSha
    diff_text: str
    files_changed: int
    bytes_size: int
    shape: str = "source"
    files: tuple[FileChange, ...] = field(default_factory=tuple)
    consensus: dict | None = None
    extraction_agreement: dict | None = None

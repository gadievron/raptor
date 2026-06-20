"""
Observation schema definitions (pure data).
"""
from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, Field, HttpUrl

from .common import (
    EvidenceSource,
    GitHubActor,
    GitHubRepository,
    IOCType,
    VerificationInfo,
)


# =============================================================================
# OBSERVATION - Something we observed
#
# Two perspectives:
# - Original event (if known): when, who, what
# - Observer: when observed, by whom, what found
#
# Sources: GitHub, Wayback, security vendors
# =============================================================================


class Observation(BaseModel):
    """Something we observed."""

    evidence_id: str

    # Original event (if known)
    original_when: datetime | None = None
    original_who: GitHubActor | None = None
    original_what: str | None = None

    # Observer
    observed_when: datetime
    observed_by: EvidenceSource
    observed_what: str

    # Context
    repository: GitHubRepository | None = None
    verification: VerificationInfo

    # State
    is_deleted: bool = False  # No longer exists at source


# -----------------------------------------------------------------------------
# Atomic observations
# -----------------------------------------------------------------------------


class CommitAuthor(BaseModel):
    name: str
    email: str
    date: datetime


class FileChange(BaseModel):
    filename: str
    status: Literal["added", "modified", "removed", "renamed"]
    additions: int = 0
    deletions: int = 0
    patch: str | None = None


class CommitObservation(Observation):
    """Commit."""

    observation_type: Literal["commit"] = "commit"
    sha: Annotated[str, Field(min_length=40, max_length=40)]
    message: str
    author: CommitAuthor
    committer: CommitAuthor
    parents: list[str] = Field(default_factory=list)
    files: list[FileChange] = Field(default_factory=list)
    is_dangling: bool = False  # Not on any branch


class IssueObservation(Observation):
    """Issue or PR."""

    observation_type: Literal["issue"] = "issue"
    issue_number: int
    is_pull_request: bool = False
    title: str | None = None
    body: str | None = None
    state: Literal["open", "closed", "merged"] | None = None


class FileObservation(Observation):
    """File content."""

    observation_type: Literal["file"] = "file"
    file_path: str
    branch: str | None = None
    content: str = ""  # File content (may be empty for large files)
    content_hash: str | None = None  # SHA256
    size_bytes: int = 0


class ForkObservation(Observation):
    """Fork relationship."""

    observation_type: Literal["fork"] = "fork"
    fork_full_name: str
    parent_full_name: str = ""  # The source repository that was forked
    fork_owner: str | None = None
    fork_repo: str | None = None
    forked_at: datetime | None = None


class BranchObservation(Observation):
    """Branch."""

    observation_type: Literal["branch"] = "branch"
    branch_name: str
    head_sha: str | None = None
    protected: bool = False


class TagObservation(Observation):
    """Tag."""

    observation_type: Literal["tag"] = "tag"
    tag_name: str
    target_sha: str | None = None


class ReleaseObservation(Observation):
    """Release."""

    observation_type: Literal["release"] = "release"
    tag_name: str
    release_name: str | None = None
    release_body: str | None = None
    created_at: datetime | None = None
    published_at: datetime | None = None
    is_prerelease: bool = False
    is_draft: bool = False


class WaybackSnapshot(BaseModel):
    """Single Wayback capture from CDX API."""

    timestamp: str  # YYYYMMDDHHMMSS format
    original: str  # Original URL that was archived
    digest: str = ""  # SHA-1 of content
    mimetype: str = ""  # MIME type
    statuscode: str = "200"  # HTTP status code as string
    length: str = ""  # Content length as string


class SnapshotObservation(Observation):
    """Wayback snapshots for a URL."""

    observation_type: Literal["snapshot"] = "snapshot"
    original_url: HttpUrl
    snapshots: list[WaybackSnapshot]
    total_snapshots: int


# -----------------------------------------------------------------------------
# IOC - Indicator of Compromise
# -----------------------------------------------------------------------------


class IOC(Observation):
    """Indicator of Compromise."""

    observation_type: Literal["ioc"] = "ioc"
    ioc_type: IOCType
    value: str
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    extracted_from: str | None = None  # Evidence ID


# -----------------------------------------------------------------------------
# Article - External documentation (blog posts, security reports)
# -----------------------------------------------------------------------------


class ArticleObservation(Observation):
    """External article documenting an incident (blog post, security report, news article)."""

    observation_type: Literal["article"] = "article"
    url: HttpUrl
    title: str
    author: str | None = None
    published_date: datetime | None = None
    source_name: str | None = None  # e.g., "404media", "mbgsec.com"
    summary: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)  # Evidence items documented in article


AnyObservation = (
    CommitObservation
    | IssueObservation
    | FileObservation
    | ForkObservation
    | BranchObservation
    | TagObservation
    | ReleaseObservation
    | SnapshotObservation
    | IOC
    | ArticleObservation
)

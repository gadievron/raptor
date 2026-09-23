"""
Observation schema definitions (pure data).
"""
from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, Field, HttpUrl, field_validator

from .common import (
    EvidenceSource,
    GitHubActor,
    GitHubRepository,
    IOCType,
    VerificationInfo,
    validate_git_ref_name,
    validate_repo_relative_path,
    validate_sha1_hex,
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
    # The full documented GitHub commits-API status set — the API also
    # emits changed/copied/unchanged, and a single such file must not
    # make evidence collection for the whole commit raise.
    status: Literal[
        "added", "modified", "removed", "renamed",
        "changed", "copied", "unchanged",
    ]
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

    @field_validator("sha")
    @classmethod
    def _sha_is_hex(cls, value: str) -> str:
        # The sha joins the verification URL; length-40 alone let
        # non-hex path-shaped values through to the API client.
        return validate_sha1_hex(value, "commit sha")


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

    @field_validator("file_path")
    @classmethod
    def _file_path_shape(cls, value: str) -> str:
        # Joins the verification URL; traversal here re-addressed the
        # contents fetch to an attacker-chosen repository.
        return validate_repo_relative_path(value, "file_path")

    @field_validator("branch")
    @classmethod
    def _branch_shape(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return validate_git_ref_name(value, "branch")


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

    @field_validator("branch_name")
    @classmethod
    def _branch_name_shape(cls, value: str) -> str:
        return validate_git_ref_name(value, "branch_name")

    @field_validator("head_sha")
    @classmethod
    def _head_sha_is_hex(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return validate_sha1_hex(value, "head_sha")


class TagObservation(Observation):
    """Tag."""

    observation_type: Literal["tag"] = "tag"
    tag_name: str
    target_sha: str | None = None

    @field_validator("tag_name")
    @classmethod
    def _tag_name_shape(cls, value: str) -> str:
        return validate_git_ref_name(value, "tag_name")

    @field_validator("target_sha")
    @classmethod
    def _target_sha_is_hex(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return validate_sha1_hex(value, "target_sha")


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

    @field_validator("tag_name")
    @classmethod
    def _tag_name_shape(cls, value: str) -> str:
        return validate_git_ref_name(value, "tag_name")


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

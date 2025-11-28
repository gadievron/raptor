"""
GitHub Forensics Verifiable Evidence Schema

Two evidence types:

1. Event - Something that happened (from GH Archive, git log)
   when, who, what

2. Observation - Something we observed (from GitHub, Wayback, security blogs)
   Original: when, who, what (if known)
   Observer: when observed, who observed, what they found
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, Field, HttpUrl


# =============================================================================
# ENUMS
# =============================================================================


class EvidenceSource(str, Enum):
    """Where evidence was obtained."""

    GHARCHIVE = "gharchive"  # GH Archive via BigQuery
    GIT = "git"  # Local git log/show
    GITHUB = "github"  # GitHub API or web
    WAYBACK = "wayback"  # Internet Archive
    SECURITY_VENDOR = "security_vendor"  # Security blogs/reports


class EventType(str, Enum):
    """GitHub event types from GH Archive."""

    PUSH = "PushEvent"
    PULL_REQUEST = "PullRequestEvent"
    ISSUES = "IssuesEvent"
    ISSUE_COMMENT = "IssueCommentEvent"
    CREATE = "CreateEvent"
    DELETE = "DeleteEvent"
    FORK = "ForkEvent"
    WATCH = "WatchEvent"
    RELEASE = "ReleaseEvent"
    MEMBER = "MemberEvent"
    PUBLIC = "PublicEvent"
    WORKFLOW_RUN = "WorkflowRunEvent"


class RefType(str, Enum):
    BRANCH = "branch"
    TAG = "tag"
    REPOSITORY = "repository"


class PRAction(str, Enum):
    OPENED = "opened"
    CLOSED = "closed"
    REOPENED = "reopened"
    MERGED = "merged"


class IssueAction(str, Enum):
    OPENED = "opened"
    CLOSED = "closed"
    REOPENED = "reopened"
    DELETED = "deleted"


class WorkflowConclusion(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    CANCELLED = "cancelled"


class IOCType(str, Enum):
    """Indicator types - opinionated, no 'other'."""

    COMMIT_SHA = "commit_sha"
    FILE_PATH = "file_path"
    FILE_HASH = "file_hash"  # SHA256 of file content
    CODE_SNIPPET = "code_snippet"  # Malicious code pattern
    EMAIL = "email"
    USERNAME = "username"
    REPOSITORY = "repository"
    TAG_NAME = "tag_name"
    BRANCH_NAME = "branch_name"
    WORKFLOW_NAME = "workflow_name"
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    API_KEY = "api_key"
    SECRET = "secret"


# =============================================================================
# COMMON MODELS
# =============================================================================


class GitHubActor(BaseModel):
    """GitHub user/actor."""

    login: str
    id: int | None = None
    is_bot: bool = False


class GitHubRepository(BaseModel):
    """GitHub repository."""

    owner: str
    name: str
    full_name: str
    id: int | None = None


class VerificationInfo(BaseModel):
    """How to verify this evidence."""

    source: EvidenceSource
    url: HttpUrl | None = None
    bigquery_table: str | None = None
    query: str | None = None


# =============================================================================
# EVENT - Something that happened
#
# when, who, what
# Sources: GH Archive, git
# =============================================================================


class Event(BaseModel):
    """Something that happened."""

    evidence_id: str
    when: datetime  # When it happened
    who: GitHubActor  # Who did it
    what: str  # What they did
    repository: GitHubRepository
    verification: VerificationInfo
    notes: str | None = None


class CommitInPush(BaseModel):
    """Commit embedded in PushEvent."""

    sha: str
    message: str
    author_name: str
    author_email: str


class PushEvent(Event):
    """Someone pushed commits."""

    event_type: Literal["push"] = "push"
    ref: str
    before_sha: str
    after_sha: str
    size: int
    commits: list[CommitInPush] = Field(default_factory=list)
    is_force_push: bool = False


class PullRequestEvent(Event):
    """PR action."""

    event_type: Literal["pull_request"] = "pull_request"
    action: PRAction
    pr_number: int
    pr_title: str
    pr_body: str | None = None
    head_sha: str | None = None
    merged: bool = False


class IssueEvent(Event):
    """Issue action."""

    event_type: Literal["issue"] = "issue"
    action: IssueAction
    issue_number: int
    issue_title: str
    issue_body: str | None = None


class IssueCommentEvent(Event):
    """Comment on issue/PR."""

    event_type: Literal["issue_comment"] = "issue_comment"
    action: Literal["created", "edited", "deleted"]
    issue_number: int
    comment_id: int
    comment_body: str


class CreateEvent(Event):
    """Branch/tag/repo created."""

    event_type: Literal["create"] = "create"
    ref_type: RefType
    ref_name: str


class DeleteEvent(Event):
    """Branch/tag deleted."""

    event_type: Literal["delete"] = "delete"
    ref_type: RefType
    ref_name: str


class ForkEvent(Event):
    """Repository forked."""

    event_type: Literal["fork"] = "fork"
    fork_full_name: str


class WorkflowRunEvent(Event):
    """GitHub Actions. Absence during commit = API attack."""

    event_type: Literal["workflow_run"] = "workflow_run"
    action: Literal["requested", "completed", "in_progress"]
    workflow_name: str
    head_sha: str
    conclusion: WorkflowConclusion | None = None


class ReleaseEvent(Event):
    """Release published."""

    event_type: Literal["release"] = "release"
    action: Literal["published", "created", "deleted"]
    tag_name: str
    release_name: str | None = None
    release_body: str | None = None


class WatchEvent(Event):
    """Repo starred."""

    event_type: Literal["watch"] = "watch"


class MemberEvent(Event):
    """Collaborator changed."""

    event_type: Literal["member"] = "member"
    action: Literal["added", "removed"]
    member: GitHubActor


class PublicEvent(Event):
    """Repo made public."""

    event_type: Literal["public"] = "public"


AnyEvent = (
    PushEvent
    | PullRequestEvent
    | IssueEvent
    | IssueCommentEvent
    | CreateEvent
    | DeleteEvent
    | ForkEvent
    | WorkflowRunEvent
    | ReleaseEvent
    | WatchEvent
    | MemberEvent
    | PublicEvent
)


# =============================================================================
# OBSERVATION - Something we observed
#
# Two sets of when/who/what:
# - Original: when/who/what of the actual event (if known)
# - Observer: when observed, who observed, what they found
#
# Sources: GitHub, Wayback, security vendors
# =============================================================================


class Observation(BaseModel):
    """
    Something we observed.

    Has two perspectives:
    - Original event (if known): when it happened, who did it, what they did
    - Observer: when we found it, who found it, what we found
    """

    evidence_id: str

    # Original event (if known)
    original_when: datetime | None = None  # When it actually happened
    original_who: GitHubActor | None = None  # Who actually did it
    original_what: str | None = None  # What actually happened

    # Observer
    observed_when: datetime  # When we/they found it
    observed_by: EvidenceSource  # Who observed (wayback, vendor, us)
    observed_what: str  # What was observed/found

    # Context
    repository: GitHubRepository | None = None
    verification: VerificationInfo
    notes: str | None = None


# -----------------------------------------------------------------------------
# Commit observations
# -----------------------------------------------------------------------------


class CommitAuthor(BaseModel):
    name: str
    email: str
    date: datetime


class CommitFileChange(BaseModel):
    filename: str
    status: Literal["added", "modified", "removed", "renamed"]
    additions: int = 0
    deletions: int = 0
    patch: str | None = None


class CommitObservation(Observation):
    """Full commit details."""

    observation_type: Literal["commit"] = "commit"
    sha: Annotated[str, Field(min_length=40, max_length=40)]
    message: str
    author: CommitAuthor
    committer: CommitAuthor
    parents: list[str] = Field(default_factory=list)
    files: list[CommitFileChange] = Field(default_factory=list)
    is_dangling: bool = False


class ForcePushedCommitRef(Observation):
    """Reference to commit overwritten by force push."""

    observation_type: Literal["force_pushed_commit"] = "force_pushed_commit"
    deleted_sha: str
    replaced_by_sha: str
    branch: str
    pusher: GitHubActor
    recovered_commit: CommitObservation | None = None


# -----------------------------------------------------------------------------
# Wayback observations
# -----------------------------------------------------------------------------


class WaybackSnapshot(BaseModel):
    """Single Wayback capture."""

    timestamp: str
    captured_at: datetime
    archive_url: HttpUrl
    original_url: HttpUrl
    status_code: int = 200


class WaybackObservation(Observation):
    """Wayback snapshots for a URL."""

    observation_type: Literal["wayback"] = "wayback"
    original_url: HttpUrl
    snapshots: list[WaybackSnapshot]
    total_snapshots: int


class RecoveredIssue(Observation):
    """Issue/PR recovered from Wayback or GH Archive."""

    observation_type: Literal["recovered_issue"] = "recovered_issue"
    issue_number: int
    is_pull_request: bool = False
    title: str | None = None
    body: str | None = None
    state: Literal["open", "closed", "merged", "unknown"] | None = None
    source_snapshot: WaybackSnapshot | None = None


class RecoveredFile(Observation):
    """File content recovered from Wayback."""

    observation_type: Literal["recovered_file"] = "recovered_file"
    file_path: str
    content: str
    content_hash: str | None = None  # SHA256
    source_snapshot: WaybackSnapshot


class RecoveredWiki(Observation):
    """Wiki page recovered from Wayback."""

    observation_type: Literal["recovered_wiki"] = "recovered_wiki"
    page_name: str
    content: str
    source_snapshot: WaybackSnapshot


class RecoveredForks(Observation):
    """Fork list recovered from Wayback."""

    observation_type: Literal["recovered_forks"] = "recovered_forks"
    forks: list[str]
    source_snapshot: WaybackSnapshot


# -----------------------------------------------------------------------------
# IOC - Indicator of Compromise (subtype of Observation)
# -----------------------------------------------------------------------------


class IOC(Observation):
    """
    Indicator of Compromise.

    Subtype of Observation. original_* fields capture the actual
    malicious event if known, observed_* captures discovery.
    """

    observation_type: Literal["ioc"] = "ioc"
    ioc_type: IOCType
    value: str
    confidence: Literal["confirmed", "high", "medium", "low"] = "medium"
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    extracted_from: str | None = None  # Evidence ID if extracted


AnyObservation = (
    CommitObservation
    | ForcePushedCommitRef
    | WaybackObservation
    | RecoveredIssue
    | RecoveredFile
    | RecoveredWiki
    | RecoveredForks
    | IOC
)


# =============================================================================
# TYPE ALIASES
# =============================================================================


AnyEvidence = AnyEvent | AnyObservation

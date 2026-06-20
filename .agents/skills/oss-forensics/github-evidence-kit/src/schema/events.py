"""
Event schema definitions (pure data).
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from .common import (
    EvidenceSource,
    GitHubActor,
    GitHubRepository,
    IssueAction,
    PRAction,
    RefType,
    VerificationInfo,
    WorkflowConclusion,
)


# =============================================================================
# EVENT - Something that happened
#
# when, who, what
# Sources: GH Archive, git
# =============================================================================


class Event(BaseModel):
    """Something that happened."""

    evidence_id: str
    when: datetime
    who: GitHubActor
    what: str
    repository: GitHubRepository
    verification: VerificationInfo


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

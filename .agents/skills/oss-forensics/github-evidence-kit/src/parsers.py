"""
GH Archive Event Parsers.

Functions for parsing GH Archive BigQuery rows into Evidence objects.
Each parser extracts structured data from raw GH Archive JSON payloads.
"""

from __future__ import annotations

import json
from typing import Any

from .helpers import (
    generate_evidence_id,
    make_actor,
    make_repo_from_full_name,
    parse_datetime_lenient,
)
from .schema.common import (
    EvidenceSource,
    GitHubActor,
    IssueAction,
    PRAction,
    RefType,
    VerificationInfo,
    WorkflowConclusion,
)
from .schema.events import (
    CommitInPush,
    CreateEvent,
    DeleteEvent,
    ForkEvent,
    IssueCommentEvent,
    IssueEvent,
    MemberEvent,
    PublicEvent,
    PullRequestEvent,
    PushEvent,
    ReleaseEvent,
    WatchEvent,
    WorkflowRunEvent,
)


class _RowContext:
    """Extracted common data from a GH Archive row."""

    __slots__ = ("row", "payload", "when", "who", "repository", "verification")

    def __init__(self, row: dict[str, Any], table: str | None = None):
        self.row = row
        self.payload = json.loads(row["payload"]) if isinstance(row["payload"], str) else row["payload"]
        self.when = parse_datetime_lenient(row.get("created_at"))
        self.who = make_actor(row.get("actor_login", "unknown"), row.get("actor_id"))

        # Extract repository name from row - try multiple locations
        repo_name = row.get("repo_name") or row.get("repo", {}).get("name")
        if not repo_name:
            # Try extracting from payload as last resort
            repo_obj = self.payload.get("repository") or row.get("repo", {})
            owner = repo_obj.get("owner", {}).get("login") if isinstance(repo_obj.get("owner"), dict) else repo_obj.get("owner")
            name = repo_obj.get("name")
            if owner and name:
                repo_name = f"{owner}/{name}"

        # Raise error if we still couldn't extract valid repo name
        if not repo_name:
            raise ValueError(
                f"Cannot extract repository name from GH Archive row. "
                f"Row ID: {row.get('id', 'unknown')}, Event Type: {row.get('type', 'unknown')}. "
                f"Available keys: {list(row.keys())}"
            )

        self.repository = make_repo_from_full_name(repo_name)

        # Determine table from timestamp if not provided
        if not table and self.when:
            year = self.when.year
            if year < 2025:
                table = f"githubarchive.year.{year}"
            else:
                month = self.when.strftime("%Y%m")
                table = f"githubarchive.month.{month}"

        self.verification = VerificationInfo(
            source=EvidenceSource.GHARCHIVE,
            bigquery_table=table,
        )


# =============================================================================
# EVENT PARSERS
# =============================================================================


def parse_push_event(row: dict[str, Any], table: str | None = None) -> PushEvent:
    """Parse GH Archive PushEvent into PushEvent evidence."""
    ctx = _RowContext(row, table)
    payload = ctx.payload

    commits = []
    for c in payload.get("commits", []):
        author = c.get("author", {})
        commits.append(
            CommitInPush(
                sha=c.get("sha", ""),
                message=c.get("message", ""),
                author_name=author.get("name", ""),
                author_email=author.get("email", ""),
            )
        )

    before_sha = payload.get("before", "0" * 40)
    after_sha = payload.get("head", payload.get("after", "0" * 40))
    size = int(payload.get("size", len(commits)))
    is_force_push = size == 0 and before_sha != "0" * 40
    ref = payload.get("ref", "")

    return PushEvent(
        evidence_id=generate_evidence_id("push", ctx.repository.full_name, after_sha),
        when=ctx.when,
        who=ctx.who,
        what=f"Pushed {size} commit(s) to {ref}",
        repository=ctx.repository,
        verification=ctx.verification,
        ref=ref,
        before_sha=before_sha,
        after_sha=after_sha,
        size=size,
        commits=commits,
        is_force_push=is_force_push,
    )


def parse_issue_event(row: dict[str, Any], table: str | None = None) -> IssueEvent:
    """Parse GH Archive IssuesEvent into IssueEvent evidence."""
    ctx = _RowContext(row, table)
    issue = ctx.payload.get("issue", {})

    action_str = ctx.payload.get("action", "opened")
    action_map = {
        "opened": IssueAction.OPENED,
        "closed": IssueAction.CLOSED,
        "reopened": IssueAction.REOPENED,
        "deleted": IssueAction.DELETED,
    }
    action = action_map.get(action_str, IssueAction.OPENED)
    issue_number = issue.get("number", 0)

    return IssueEvent(
        evidence_id=generate_evidence_id("issue", ctx.repository.full_name, str(issue_number), action_str),
        when=ctx.when,
        who=ctx.who,
        what=f"Issue #{issue_number} {action_str}",
        repository=ctx.repository,
        verification=ctx.verification,
        action=action,
        issue_number=issue_number,
        issue_title=issue.get("title", ""),
        issue_body=issue.get("body"),
    )


def parse_create_event(row: dict[str, Any], table: str | None = None) -> CreateEvent:
    """Parse GH Archive CreateEvent into CreateEvent evidence."""
    ctx = _RowContext(row, table)

    ref_type_str = ctx.payload.get("ref_type", "branch")
    ref_type_map = {"branch": RefType.BRANCH, "tag": RefType.TAG, "repository": RefType.REPOSITORY}
    ref_type = ref_type_map.get(ref_type_str, RefType.BRANCH)
    ref_name = ctx.payload.get("ref", "")

    return CreateEvent(
        evidence_id=generate_evidence_id("create", ctx.repository.full_name, ref_type_str, ref_name),
        when=ctx.when,
        who=ctx.who,
        what=f"Created {ref_type_str} '{ref_name}'",
        repository=ctx.repository,
        verification=ctx.verification,
        ref_type=ref_type,
        ref_name=ref_name,
    )


def parse_pull_request_event(row: dict[str, Any], table: str | None = None) -> PullRequestEvent:
    """Parse GH Archive PullRequestEvent into PullRequestEvent evidence."""
    ctx = _RowContext(row, table)
    pr = ctx.payload.get("pull_request", {})

    action_str = ctx.payload.get("action", "opened")
    action_map = {"opened": PRAction.OPENED, "closed": PRAction.CLOSED, "reopened": PRAction.REOPENED}
    action = action_map.get(action_str, PRAction.OPENED)
    if action_str == "closed" and pr.get("merged"):
        action = PRAction.MERGED

    pr_number = pr.get("number", 0)

    return PullRequestEvent(
        evidence_id=generate_evidence_id("pr", ctx.repository.full_name, str(pr_number), action_str),
        when=ctx.when,
        who=ctx.who,
        what=f"PR #{pr_number} {action_str}",
        repository=ctx.repository,
        verification=ctx.verification,
        action=action,
        pr_number=pr_number,
        pr_title=pr.get("title", ""),
        pr_body=pr.get("body"),
        head_sha=pr.get("head", {}).get("sha"),
        merged=pr.get("merged", False),
    )


def parse_issue_comment_event(row: dict[str, Any], table: str | None = None) -> IssueCommentEvent:
    """Parse GH Archive IssueCommentEvent into IssueCommentEvent evidence."""
    ctx = _RowContext(row, table)
    issue = ctx.payload.get("issue", {})
    comment = ctx.payload.get("comment", {})
    comment_id = comment.get("id", 0)

    return IssueCommentEvent(
        evidence_id=generate_evidence_id("comment", ctx.repository.full_name, str(comment_id)),
        when=ctx.when,
        who=ctx.who,
        what=f"Comment on issue #{issue.get('number')}",
        repository=ctx.repository,
        verification=ctx.verification,
        action=ctx.payload.get("action", "created"),
        issue_number=issue.get("number", 0),
        comment_id=comment_id,
        comment_body=comment.get("body", ""),
    )


def parse_watch_event(row: dict[str, Any], table: str | None = None) -> WatchEvent:
    """Parse GH Archive WatchEvent into WatchEvent evidence."""
    ctx = _RowContext(row, table)

    return WatchEvent(
        evidence_id=generate_evidence_id("watch", ctx.repository.full_name, ctx.who.login),
        when=ctx.when,
        who=ctx.who,
        what=f"User {ctx.who.login} starred repository",
        repository=ctx.repository,
        verification=ctx.verification,
    )


def parse_fork_event(row: dict[str, Any], table: str | None = None) -> ForkEvent:
    """Parse GH Archive ForkEvent into ForkEvent evidence."""
    ctx = _RowContext(row, table)
    forkee = ctx.payload.get("forkee", {})
    fork_full_name = forkee.get("full_name", f"{ctx.who.login}/{ctx.repository.name}")

    return ForkEvent(
        evidence_id=generate_evidence_id("fork", ctx.repository.full_name, fork_full_name),
        when=ctx.when,
        who=ctx.who,
        what=f"Forked to {fork_full_name}",
        repository=ctx.repository,
        verification=ctx.verification,
        fork_full_name=fork_full_name,
    )


def parse_delete_event(row: dict[str, Any], table: str | None = None) -> DeleteEvent:
    """Parse GH Archive DeleteEvent into DeleteEvent evidence."""
    ctx = _RowContext(row, table)

    ref_type_str = ctx.payload.get("ref_type", "branch")
    ref_type_map = {"branch": RefType.BRANCH, "tag": RefType.TAG}
    ref_type = ref_type_map.get(ref_type_str, RefType.BRANCH)
    ref_name = ctx.payload.get("ref", "")

    return DeleteEvent(
        evidence_id=generate_evidence_id("delete", ctx.repository.full_name, ref_type_str, ref_name),
        when=ctx.when,
        who=ctx.who,
        what=f"Deleted {ref_type_str} '{ref_name}'",
        repository=ctx.repository,
        verification=ctx.verification,
        ref_type=ref_type,
        ref_name=ref_name,
    )


def parse_member_event(row: dict[str, Any], table: str | None = None) -> MemberEvent:
    """Parse GH Archive MemberEvent into MemberEvent evidence."""
    ctx = _RowContext(row, table)
    member = ctx.payload.get("member", {})
    action = ctx.payload.get("action", "added")

    # MemberEvent actions in GitHub are: added, removed, edited
    action_map = {"added": "added", "removed": "removed"}
    normalized_action = action_map.get(action, "added")

    return MemberEvent(
        evidence_id=generate_evidence_id("member", ctx.repository.full_name, member.get("login", ""), action),
        when=ctx.when,
        who=ctx.who,
        what=f"Collaborator {member.get('login', 'unknown')} {normalized_action}",
        repository=ctx.repository,
        verification=ctx.verification,
        action=normalized_action,
        member=GitHubActor(login=member.get("login", "unknown"), id=member.get("id")),
    )


def parse_public_event(row: dict[str, Any], table: str | None = None) -> PublicEvent:
    """Parse GH Archive PublicEvent into PublicEvent evidence."""
    ctx = _RowContext(row, table)

    return PublicEvent(
        evidence_id=generate_evidence_id("public", ctx.repository.full_name, str(ctx.when.timestamp())),
        when=ctx.when,
        who=ctx.who,
        what=f"Repository {ctx.repository.full_name} made public",
        repository=ctx.repository,
        verification=ctx.verification,
    )


def parse_release_event(row: dict[str, Any], table: str | None = None) -> ReleaseEvent:
    """Parse GH Archive ReleaseEvent into ReleaseEvent evidence."""
    ctx = _RowContext(row, table)
    release = ctx.payload.get("release", {})
    action = ctx.payload.get("action", "published")
    tag_name = release.get("tag_name", "")

    # Normalize action to valid Literal values
    action_map = {"published": "published", "created": "created", "deleted": "deleted"}
    normalized_action = action_map.get(action, "published")

    return ReleaseEvent(
        evidence_id=generate_evidence_id("release", ctx.repository.full_name, tag_name, action),
        when=ctx.when,
        who=ctx.who,
        what=f"Release {tag_name} {normalized_action}",
        repository=ctx.repository,
        verification=ctx.verification,
        action=normalized_action,
        tag_name=tag_name,
        release_name=release.get("name"),
        release_body=release.get("body"),
    )


def parse_workflow_run_event(row: dict[str, Any], table: str | None = None) -> WorkflowRunEvent:
    """Parse GH Archive WorkflowRunEvent into WorkflowRunEvent evidence."""
    ctx = _RowContext(row, table)
    workflow_run = ctx.payload.get("workflow_run", {})
    action = ctx.payload.get("action", "requested")

    # Normalize action
    action_map = {"requested": "requested", "completed": "completed", "in_progress": "in_progress"}
    normalized_action = action_map.get(action, "requested")

    # Parse conclusion if completed
    conclusion = None
    if normalized_action == "completed":
        conclusion_str = workflow_run.get("conclusion", "")
        conclusion_map = {"success": WorkflowConclusion.SUCCESS, "failure": WorkflowConclusion.FAILURE, "cancelled": WorkflowConclusion.CANCELLED}
        conclusion = conclusion_map.get(conclusion_str)

    workflow_name = workflow_run.get("name", "unknown")
    head_sha = workflow_run.get("head_sha", "0" * 40)

    return WorkflowRunEvent(
        evidence_id=generate_evidence_id("workflow", ctx.repository.full_name, workflow_name, head_sha[:8]),
        when=ctx.when,
        who=ctx.who,
        what=f"Workflow '{workflow_name}' {normalized_action}",
        repository=ctx.repository,
        verification=ctx.verification,
        action=normalized_action,
        workflow_name=workflow_name,
        head_sha=head_sha,
        conclusion=conclusion,
    )


# =============================================================================
# DISPATCHER
# =============================================================================

_PARSERS = {
    "PushEvent": parse_push_event,
    "IssuesEvent": parse_issue_event,
    "CreateEvent": parse_create_event,
    "DeleteEvent": parse_delete_event,
    "PullRequestEvent": parse_pull_request_event,
    "IssueCommentEvent": parse_issue_comment_event,
    "WatchEvent": parse_watch_event,
    "ForkEvent": parse_fork_event,
    "MemberEvent": parse_member_event,
    "PublicEvent": parse_public_event,
    "ReleaseEvent": parse_release_event,
    "WorkflowRunEvent": parse_workflow_run_event,
}


def parse_gharchive_event(row: dict[str, Any], table: str | None = None) -> Any:
    """Parse any GH Archive event by dispatching to appropriate parser.

    Args:
        row: GH Archive BigQuery row data
        table: Optional BigQuery table name (e.g., 'githubarchive.year.2024').
               If not provided, will be inferred from the event timestamp.
    """
    event_type = row.get("type", "")
    parser = _PARSERS.get(event_type)
    if parser is None:
        supported = ", ".join(_PARSERS.keys())
        raise ValueError(f"Unsupported GH Archive event type: {event_type}. Supported: {supported}")
    return parser(row, table)
